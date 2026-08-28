import * as crypto from 'crypto';
import axios from 'axios';
import { AsnConvert } from '@peculiar/asn1-schema';
import { OctetString } from '@peculiar/asn1-schema';
import { TimeStampReq, TimeStampResp, PKIStatus, TimeStampReqVersion, MessageImprint } from '@peculiar/asn1-tsp';
import { AlgorithmIdentifier } from '@peculiar/asn1-x509';
import { ContentInfo, SignedData } from '@peculiar/asn1-cms';
import { TSTInfo } from '@peculiar/asn1-tsp';
import { createLogger } from '../logging/index.js';

const logger = createLogger('tsa-client');

// The OID a MessageImprint's hashAlgorithm carries for plain SHA-256 --
// same digest CertificateService already uses for certificateHash, so the
// TSA is asked to timestamp the exact same hash, never recomputed.
const SHA256_OID = '2.16.840.1.101.3.4.2.1';

export interface TsaTimestampInfo {
  status: 'OBTAINED' | 'FAILED';
  // Base64 of the *entire raw, unmodified* TimeStampResp DER bytes exactly
  // as received. Never re-serialize the parsed structure back to DER --
  // that risks BER/DER canonicalization drift silently invalidating the
  // very signature this is supposed to prove. Present only when OBTAINED.
  token?: string;
  // ISO string from TSTInfo.genTime. Informational only -- a verifier must
  // re-derive genTime from the token itself, never trust this field alone.
  timestamp?: string;
  // Which endpoint issued this -- lets a verifier/auditor know which root
  // CA to pin against if the TSA provider is ever changed.
  tsaUrl: string;
  attemptedAt: string;
  // Operator-facing only; short failure reason, present only when FAILED.
  error?: string;
}

// Wraps a single external RFC 3161 Time-Stamping Authority. Never throws --
// matches GithubActionsClient's established pattern for optional external
// integrations whose failure must never affect the operation they're
// attached to. Unlike GithubActionsClient (fired from an admin-only
// route), this sits on CertificateService.issueAndStoreCertificate's
// synchronous path, reached via the real user-facing
// POST /deletion-requests/:id/advance -- so failure here must resolve
// quickly (see the timeout below) and never throw, but a caller *does*
// have to await it (fire-and-forget would risk the exact scale-to-zero bug
// already found and fixed for the JWKS-mirror dispatch, since this service
// runs min_instance_count=0).
export class TsaClient {
  constructor(private readonly tsaUrl: string) {}

  async requestTimestamp(certificateHashHex: string): Promise<TsaTimestampInfo> {
    const attemptedAt = new Date().toISOString();
    try {
      const digest = Buffer.from(certificateHashHex, 'hex');

      // Positive INTEGER per RFC 3161 -- clear the top bit so the encoded
      // nonce is never read as negative (same convention every RFC 3161
      // client uses, including openssl's own `ts -query`).
      const nonce = crypto.randomBytes(8);
      nonce[0] &= 0x7f;

      const req = new TimeStampReq({
        version: TimeStampReqVersion.v1,
        messageImprint: new MessageImprint({
          hashAlgorithm: new AlgorithmIdentifier({ algorithm: SHA256_OID }),
          hashedMessage: new OctetString(digest),
        }),
        nonce: nonce.buffer.slice(nonce.byteOffset, nonce.byteOffset + nonce.byteLength),
        // Ask the TSA to embed its own signing cert in the response so a
        // verifier doesn't need a separate fetch for it -- only the pinned
        // root CA needs to be supplied out-of-band.
        certReq: true,
      });

      const reqBytes = Buffer.from(AsnConvert.serialize(req));

      const res = await axios.post(this.tsaUrl, reqBytes, {
        headers: {
          'Content-Type': 'application/timestamp-query',
          Accept: 'application/timestamp-reply',
        },
        responseType: 'arraybuffer',
        // Bounded short: this is on a real user-facing request path
        // (deletion-request advance), not an admin-only route, so a slow
        // or hung TSA must not stall that call for long. Real observed
        // latency against FreeTSA was ~230ms.
        timeout: 5_000,
        validateStatus: () => true,
      });

      if (res.status !== 200) {
        logger.error({ status: res.status, tsaUrl: this.tsaUrl }, 'TSA request returned non-200');
        return { status: 'FAILED', tsaUrl: this.tsaUrl, attemptedAt, error: `HTTP ${res.status}` };
      }

      const responseBytes: Buffer = Buffer.from(res.data as ArrayBuffer);
      const resp = AsnConvert.parse(responseBytes, TimeStampResp);

      if (resp.status.status !== PKIStatus.granted && resp.status.status !== PKIStatus.grantedWithMods) {
        logger.error({ status: resp.status.status, tsaUrl: this.tsaUrl }, 'TSA declined the timestamp request');
        return { status: 'FAILED', tsaUrl: this.tsaUrl, attemptedAt, error: `PKIStatus ${resp.status.status}` };
      }
      if (!resp.timeStampToken) {
        logger.error({ tsaUrl: this.tsaUrl }, 'TSA response granted but carried no timeStampToken');
        return { status: 'FAILED', tsaUrl: this.tsaUrl, attemptedAt, error: 'missing timeStampToken' };
      }

      // Sanity-check the token actually answers *our* request before
      // trusting/persisting it -- defensive; should never fail against a
      // well-behaved TSA, but a token that doesn't match what we asked for
      // has no value stored. Full cryptographic verification is
      // deliberately not duplicated here -- that's src/crypto/tsa-verify.ts's
      // job, run independently at verify time.
      const contentInfo = AsnConvert.parse(
        AsnConvert.serialize(resp.timeStampToken),
        ContentInfo
      );
      const signedData = AsnConvert.parse(contentInfo.content, SignedData);
      const eContent = signedData.encapContentInfo.eContent?.single;
      if (!eContent) {
        return { status: 'FAILED', tsaUrl: this.tsaUrl, attemptedAt, error: 'no TSTInfo content in response' };
      }
      const tstInfo = AsnConvert.parse(eContent.buffer, TSTInfo);

      const imprintMatches = Buffer.from(tstInfo.messageImprint.hashedMessage.buffer).equals(digest);
      if (!imprintMatches) {
        logger.error({ tsaUrl: this.tsaUrl }, 'TSA response messageImprint does not match the hash we sent');
        return { status: 'FAILED', tsaUrl: this.tsaUrl, attemptedAt, error: 'messageImprint mismatch' };
      }
      if (tstInfo.nonce) {
        const respNonce = Buffer.from(tstInfo.nonce);
        const reqNonce = Buffer.from(req.nonce!);
        if (!respNonce.equals(reqNonce)) {
          logger.error({ tsaUrl: this.tsaUrl }, 'TSA response nonce does not match the request nonce');
          return { status: 'FAILED', tsaUrl: this.tsaUrl, attemptedAt, error: 'nonce mismatch' };
        }
      }

      return {
        status: 'OBTAINED',
        token: responseBytes.toString('base64'),
        timestamp: tstInfo.genTime.toISOString(),
        tsaUrl: this.tsaUrl,
        attemptedAt,
      };
    } catch (error) {
      logger.error({ error, tsaUrl: this.tsaUrl }, 'TSA timestamp request threw');
      return {
        status: 'FAILED',
        tsaUrl: this.tsaUrl,
        attemptedAt,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

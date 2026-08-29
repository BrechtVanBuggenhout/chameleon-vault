import * as crypto from 'crypto';
import axios from 'axios';
import { CloudKMSClient } from './cloud-kms.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('rekor-client');

export interface RekorLogEntryInfo {
  status: 'PUBLISHED' | 'FAILED';
  // Rekor's own sequence number for this entry, and the UUID it's stored
  // under -- both are how a monitor/verifier looks the entry back up
  // independent of Chameleon's own API. Present only when PUBLISHED.
  logIndex?: number;
  entryUuid?: string;
  rekorUrl: string;
  attemptedAt: string;
  // Operator-facing only; short failure reason, present only when FAILED.
  error?: string;
}

// Publishes {certificateHash, previousCertificateHash} to a public Sigstore
// Rekor transparency log -- the independent-of-Chameleon witness that a
// destruction certificate with this hash existed at this point in the log,
// so Chameleon alone can no longer decide what its own certificate history
// looks like after the fact. Deliberately publishes hashes only, never
// tenantId/userId -- same principle as the existing certificate-chain-by-hash
// lookup (a hash is only knowable to someone who already holds a real
// chained certificate; the public log must not become an enumerable record
// of who was deleted when).
//
// Never throws -- matches TsaClient's established pattern for an optional
// external integration on CertificateService.issueAndStoreCertificate's
// synchronous path (see that class's own comment for why fire-and-forget
// is the wrong shape here: this service runs min_instance_count=0, and Cloud
// Run can reap an instance the moment a response is sent).
export class RekorClient {
  constructor(
    private readonly rekorUrl: string,
    private readonly kmsClient: CloudKMSClient,
    private readonly getSigningKeyVersionPath: () => Promise<string>
  ) {}

  // Lets an outside verifier independently confirm that the public key
  // embedded in any given Rekor entry (spec.signature.publicKey.content) is
  // really the one Chameleon publishes, rather than trusting the entry's own
  // self-reported key alone -- see GET /rekor-signing-public-key.
  async getPublicKeyPem(): Promise<string> {
    const keyVersionPath = await this.getSigningKeyVersionPath();
    return this.kmsClient.getPublicKey(keyVersionPath);
  }

  async publishCertificateHash(certificateHash: string, previousCertificateHash: string | null): Promise<RekorLogEntryInfo> {
    const attemptedAt = new Date().toISOString();
    try {
      // Canonical, fixed two-key shape -- no field-ordering ambiguity to
      // worry about, unlike a general-purpose JSON canonicalization problem.
      const payload = JSON.stringify({ certificateHash, previousCertificateHash });
      const payloadDigestHex = crypto.createHash('sha256').update(payload).digest('hex');

      const keyVersionPath = await this.getSigningKeyVersionPath();

      // Reuses CloudKMSClient.asymmetricSign, which itself hashes `payload`
      // with SHA-256 before calling KMS -- so the digest KMS actually signs
      // is exactly payloadDigestHex, computed once, never twice. KMS returns
      // base64url; Rekor's API expects standard base64.
      const signatureBase64Url = await this.kmsClient.asymmetricSign(payload, keyVersionPath);
      const signatureBase64 = Buffer.from(signatureBase64Url, 'base64url').toString('base64');
      const publicKeyPem = await this.kmsClient.getPublicKey(keyVersionPath);

      const res = await axios.post(
        `${this.rekorUrl}/api/v1/log/entries`,
        {
          kind: 'hashedrekord',
          apiVersion: '0.0.1',
          spec: {
            signature: {
              content: signatureBase64,
              publicKey: { content: Buffer.from(publicKeyPem).toString('base64') },
            },
            data: {
              hash: { algorithm: 'sha256', value: payloadDigestHex },
            },
          },
        },
        {
          headers: { 'Content-Type': 'application/json' },
          // Bounded short, same reasoning as TsaClient: this sits on the
          // real user-facing deletion-request advance path.
          timeout: 5_000,
          validateStatus: () => true,
        }
      );

      if (res.status !== 201) {
        logger.error({ status: res.status, rekorUrl: this.rekorUrl, body: res.data }, 'Rekor entry submission returned non-201');
        return { status: 'FAILED', rekorUrl: this.rekorUrl, attemptedAt, error: `HTTP ${res.status}` };
      }

      // Response is a single-key object keyed by a server-generated entry
      // UUID -- confirmed against the real public Rekor API, 2026-08-29.
      const entryUuid = Object.keys(res.data)[0];
      const entry = entryUuid ? res.data[entryUuid] : undefined;

      return {
        status: 'PUBLISHED',
        entryUuid,
        logIndex: entry?.logIndex,
        rekorUrl: this.rekorUrl,
        attemptedAt,
      };
    } catch (error) {
      logger.error({ error, rekorUrl: this.rekorUrl }, 'Rekor entry submission threw');
      return {
        status: 'FAILED',
        rekorUrl: this.rekorUrl,
        attemptedAt,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

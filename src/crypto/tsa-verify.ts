import * as crypto from 'crypto';
import * as asn1js from 'asn1js';
import { AsnConvert, AsnSerializer } from '@peculiar/asn1-schema';
import { TimeStampResp, TSTInfo, PKIStatus } from '@peculiar/asn1-tsp';
import { ContentInfo, SignedData } from '@peculiar/asn1-cms';
import type { TsaTimestampInfo } from '../gcp/tsa-client.js';

// RFC 5652 id-messageDigest attribute OID -- not exported as a constant by
// @peculiar/asn1-cms (only id-signedData/id-data/etc. are), so it's
// hardcoded here with this comment as its provenance.
const MESSAGE_DIGEST_ATTR_OID = '1.2.840.113549.1.9.4';

// Maps the OIDs actually seen on real digest/signature algorithm
// identifiers to Node crypto digest names. Confirmed live against FreeTSA
// (2026-08-28): its responses use combined signature+digest OIDs like
// ecdsa-with-SHA512 -- never assume a hash size "naturally pairs" with a
// key's curve/modulus size (FreeTSA's P-384 key actually signs with
// SHA-512, not SHA-384). Extend this table, never hardcode an algorithm
// name at a call site.
const OID_TO_DIGEST_NAME: Record<string, string> = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
  '1.2.840.10045.4.3.2': 'sha256', // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3': 'sha384', // ecdsa-with-SHA384
  '1.2.840.10045.4.3.4': 'sha512', // ecdsa-with-SHA512, confirmed live from FreeTSA
  '1.2.840.113549.1.1.11': 'sha256', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12': 'sha384', // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13': 'sha512', // sha512WithRSAEncryption
};

export type TsaVerificationResult =
  | { outcome: 'VALID'; genTime: Date }
  | { outcome: 'INVALID'; reason: string }
  | { outcome: 'ABSENT' }
  | { outcome: 'RECORDED_FAILURE' };

function findChildByContextTag(seq: asn1js.Sequence, tagNumber: number): asn1js.BaseBlock | null {
  for (const child of seq.valueBlock.value) {
    const idBlock = (child as { idBlock: { tagClass: number; tagNumber: number } }).idBlock;
    if (idBlock.tagClass === 3 && idBlock.tagNumber === tagNumber) {
      return child as asn1js.BaseBlock;
    }
  }
  return null;
}

// The one genuinely tricky step: RFC 5652 5.4 requires a CMS signature over
// the signedAttrs SET re-encoded as a universal SET OF (tag 0x31), not the
// [0] IMPLICIT bytes (tag 0xA0) actually present in the SignerInfo. Content
// and length bytes are identical either way -- only the leading identifier
// byte differs -- so this is a raw byte swap, not a re-serialization.
// @peculiar/asn1-cms's SignerInfo declares a `signedAttrsRaw` field but
// never actually populates it during parsing (confirmed empirically against
// a real response), so this is extracted manually via asn1js's lower-level
// API, which does retain each node's own raw encoded bytes.
function extractReencodedSignedAttrs(responseBytes: Buffer): Buffer {
  const parsed = asn1js.fromBER(new Uint8Array(responseBytes).buffer);
  if (parsed.offset === -1) throw new Error('failed to parse TimeStampResp DER');

  const respSeq = parsed.result as asn1js.Sequence;
  const contentInfoSeq = respSeq.valueBlock.value[1] as asn1js.Sequence; // timeStampToken
  const explicitContentWrapper = contentInfoSeq.valueBlock.value[1] as asn1js.Constructed;
  const signedDataSeq = explicitContentWrapper.valueBlock.value[0] as asn1js.Sequence;

  // signerInfos is SignedData's last field (mandatory, always last in the
  // sequence regardless of which optional fields preceded it).
  const sdChildren = signedDataSeq.valueBlock.value;
  const signerInfosSet = sdChildren[sdChildren.length - 1] as asn1js.Set;
  const firstSignerInfo = signerInfosSet.valueBlock.value[0] as asn1js.Sequence;

  const signedAttrsNode = findChildByContextTag(firstSignerInfo, 0);
  if (!signedAttrsNode) throw new Error('SignerInfo has no [0] signedAttrs element');

  const raw = Buffer.from(signedAttrsNode.toBER(false));
  const reencoded = Buffer.from(raw);
  reencoded[0] = 0x31; // SET, universal, constructed -- see comment above
  return reencoded;
}

export async function verifyTsaTimestamp(
  certificateJwt: string,
  tsaTimestamp: TsaTimestampInfo | undefined,
  pinnedRootCaPem: string
): Promise<TsaVerificationResult> {
  if (!tsaTimestamp) return { outcome: 'ABSENT' };
  if (tsaTimestamp.status === 'FAILED') return { outcome: 'RECORDED_FAILURE' };
  if (!tsaTimestamp.token) return { outcome: 'INVALID', reason: 'status OBTAINED but no token stored' };

  try {
    const responseBytes = Buffer.from(tsaTimestamp.token, 'base64');
    const resp = AsnConvert.parse(responseBytes, TimeStampResp);

    if (resp.status.status !== PKIStatus.granted && resp.status.status !== PKIStatus.grantedWithMods) {
      return { outcome: 'INVALID', reason: `stored token has non-granted PKIStatus ${resp.status.status}` };
    }
    if (!resp.timeStampToken) {
      return { outcome: 'INVALID', reason: 'stored token has no timeStampToken' };
    }

    const contentInfo = AsnConvert.parse(AsnConvert.serialize(resp.timeStampToken), ContentInfo);
    if (contentInfo.contentType !== '1.2.840.113549.1.7.2') {
      return { outcome: 'INVALID', reason: `unexpected contentType ${contentInfo.contentType}` };
    }
    const signedData = AsnConvert.parse(contentInfo.content, SignedData);

    const eContent = signedData.encapContentInfo.eContent?.single;
    if (!eContent) return { outcome: 'INVALID', reason: 'no TSTInfo content in token' };
    const tstInfo = AsnConvert.parse(eContent.buffer, TSTInfo);

    // Never trust a stored hash -- recompute independently and compare
    // against what the TSA actually attested to.
    const computedCertHash = crypto.createHash('sha256').update(certificateJwt).digest();
    const storedImprint = Buffer.from(tstInfo.messageImprint.hashedMessage.buffer);
    if (!computedCertHash.equals(storedImprint)) {
      return { outcome: 'INVALID', reason: 'messageImprint does not match sha256(certificate)' };
    }

    if (signedData.signerInfos.length !== 1) {
      return { outcome: 'INVALID', reason: `expected exactly 1 signerInfo, found ${signedData.signerInfos.length}` };
    }
    const signerInfo = signedData.signerInfos[0];

    const digestAlgName = OID_TO_DIGEST_NAME[signerInfo.digestAlgorithm.algorithm];
    const sigAlgName = OID_TO_DIGEST_NAME[signerInfo.signatureAlgorithm.algorithm];
    if (!digestAlgName || !sigAlgName) {
      return {
        outcome: 'INVALID',
        reason: `unsupported algorithm OID (digest=${signerInfo.digestAlgorithm.algorithm}, signature=${signerInfo.signatureAlgorithm.algorithm})`,
      };
    }

    if (!signerInfo.signedAttrs || signerInfo.signedAttrs.length === 0) {
      return { outcome: 'INVALID', reason: 'SignerInfo has no signedAttrs' };
    }

    // CMS-internal integrity: the messageDigest signed attribute must equal
    // hash(eContent) using the SignerInfo's own digest algorithm -- distinct
    // from the messageImprint check above, which used our chosen sha256 for
    // the TSTInfo request itself, not necessarily the same algorithm.
    const messageDigestAttr = signerInfo.signedAttrs.find((a) => a.attrType === MESSAGE_DIGEST_ATTR_OID);
    if (!messageDigestAttr) {
      return { outcome: 'INVALID', reason: 'signedAttrs missing messageDigest attribute' };
    }
    const mdParsed = asn1js.fromBER(messageDigestAttr.attrValues[0]);
    if (mdParsed.offset === -1) {
      return { outcome: 'INVALID', reason: 'could not parse messageDigest attribute value' };
    }
    const storedDigest = Buffer.from((mdParsed.result as asn1js.OctetString).valueBlock.valueHexView);
    const computedDigest = crypto.createHash(digestAlgName).update(Buffer.from(eContent.buffer)).digest();
    if (!storedDigest.equals(computedDigest)) {
      return { outcome: 'INVALID', reason: 'messageDigest attribute does not match hash(eContent)' };
    }

    // The one genuinely tricky verification step -- see the function's own
    // comment.
    const reencodedSignedAttrs = extractReencodedSignedAttrs(responseBytes);

    if (!signedData.certificates || signedData.certificates.length === 0) {
      return { outcome: 'INVALID', reason: 'no signing certificate embedded in token' };
    }
    const leafCertChoice = signedData.certificates[0];
    if (!leafCertChoice.certificate) {
      return { outcome: 'INVALID', reason: 'embedded certificate is not a plain X.509 Certificate' };
    }
    const leafCertDer = Buffer.from(AsnSerializer.serialize(leafCertChoice.certificate));
    const leafCert = new crypto.X509Certificate(leafCertDer);

    const signatureValid = crypto.verify(
      sigAlgName,
      reencodedSignedAttrs,
      leafCert.publicKey,
      Buffer.from(signerInfo.signature.buffer)
    );
    if (!signatureValid) {
      return { outcome: 'INVALID', reason: 'CMS signature verification failed' };
    }

    // Pinned trust anchor, never fetched live -- fetching your own trust
    // anchor from the site you're verifying would be circular.
    const rootCert = new crypto.X509Certificate(pinnedRootCaPem);
    if (!leafCert.checkIssued(rootCert) || !leafCert.verify(rootCert.publicKey)) {
      return { outcome: 'INVALID', reason: 'leaf certificate does not chain to the pinned root CA' };
    }

    // A long-term timestamp must remain trustworthy even after the leaf
    // cert has since expired -- check validity as of the timestamped time,
    // not "now".
    const genTime = tstInfo.genTime;
    if (genTime < new Date(leafCert.validFrom) || genTime > new Date(leafCert.validTo)) {
      return { outcome: 'INVALID', reason: 'genTime falls outside the signing certificate\'s validity window' };
    }

    return { outcome: 'VALID', genTime };
  } catch (error) {
    return { outcome: 'INVALID', reason: error instanceof Error ? error.message : String(error) };
  }
}

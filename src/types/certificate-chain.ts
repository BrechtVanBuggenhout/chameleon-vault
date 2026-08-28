import type { TsaTimestampInfo } from '../gcp/tsa-client.js';

// Per-tenant chain-of-custody state for the Certificate of Destruction log.
// One document per tenant -- the current chain head. See
// CertificateChainRepository.appendToChain for how this is advanced.
export interface CertificateChainState {
  tenant_id: string;
  sequence: number;
  last_hash: string | null;
  last_deletion_request_id: string | null;
  updated_at: Date;
}

// One entry per issued certificate, keyed by the certificate's own hash --
// lets a verifier walk previousCertificateHash backward through the chain
// (fetch the cert with hash X, read its previousCertificateHash, repeat)
// without exposing a by-sequence lookup that would let anyone enumerate a
// tenant's full deletion history. A hash is only known to someone who
// already holds a real chained certificate, so this index is safe to expose
// unauthenticated.
export interface CertificateChainEntry {
  tenant_id: string;
  sequence: number;
  previous_hash: string | null;
  deletion_request_id: string;
  created_at: Date;
  // Absent entirely (undefined) means either: RFC 3161 timestamping was
  // disabled when this certificate was issued, or -- for any certificate
  // issued before this field existed at all -- it was never attempted.
  // These two cases are permanently indistinguishable for pre-existing
  // certificates; there is no way to retroactively obtain a third-party
  // attestation for a certificate's *original* issuance time after the
  // fact (a timestamp obtained later would only prove the certificate
  // existed by the later date, defeating the purpose). This best-effort
  // Firestore copy is a convenience for internal audit tooling querying
  // this collection directly -- the GCS-stored certificate wrapper (see
  // GCSClient.uploadCertificate) is the actual source of truth read by
  // the public verification API.
  tsaTimestamp?: TsaTimestampInfo;
}

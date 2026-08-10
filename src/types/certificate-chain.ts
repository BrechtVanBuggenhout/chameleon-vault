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
}

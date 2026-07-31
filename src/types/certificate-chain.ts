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

export interface AnalystAccess {
  claim_token_hash: string;
  credential_key_hash?: string;
  tenant_id: string;
  analyst_email: string;
  created_at: Date;
  expires_at: Date;
  claimed_at?: Date;
  revoked_at?: Date;
}

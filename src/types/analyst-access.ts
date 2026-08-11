export interface AnalystAccess {
  claim_token_hash: string;
  credential_key_hash?: string;
  tenant_id: string;
  analyst_email: string;
  created_at: Date;
  expires_at: Date;
  claimed_at?: Date;
  revoked_at?: Date;
  // Absent means 'claim_link' (every record before this field existed came
  // from that flow). 'console_session' records are minted directly by
  // POST /admin/session-credentials on behalf of a logged-in console user --
  // no claim step, already "claimed" the moment they're created.
  source?: 'claim_link' | 'console_session';
  // Only set for 'console_session' records. Distinct from expires_at, which
  // is the *claim token's* expiry (irrelevant once a claim-link credential
  // is issued -- that credential is durable until revoked). A session
  // credential is deliberately short-lived instead, re-minted per console
  // session rather than handed out standing.
  credential_expires_at?: Date;
}

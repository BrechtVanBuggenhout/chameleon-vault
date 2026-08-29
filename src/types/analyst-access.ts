export interface AnalystAccess {
  claim_token_hash: string;
  credential_key_hash?: string;
  tenant_id: string;
  analyst_email: string;
  created_at: Date;
  expires_at: Date;
  claimed_at?: Date;
  revoked_at?: Date;
  // Absent means 'analyst' (every record before this field existed was one).
  // 'auditor' credentials are scoped to a single, minimal route
  // (GET /audit/key-status/:userId) -- see AUDITOR_CREDENTIAL_EXACT_PATHS in
  // middleware/auth.ts. Reuses this same claim-link/session-credential
  // machinery rather than a parallel system, since the underlying need
  // (narrowly-scoped, individually-attributable, revocable credential) is
  // identical -- only the allowed-paths set differs by role.
  role?: 'analyst' | 'auditor';
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

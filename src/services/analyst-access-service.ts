import { randomBytes, createHash } from 'crypto';
import { AnalystAccessRepository } from '../gcp/analyst-access-repository.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('analyst-access-service');

// One-time claim links expire after a week -- long enough for a customer's
// admin to forward it to a new hire, short enough that a stale unclaimed
// link isn't a standing credential-in-waiting.
const CLAIM_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

// Console-session credentials are re-minted per console session rather than
// handed out standing -- an hour is long enough to cover a normal working
// session's worth of registry/deletion-request calls without needing a
// refresh mid-task, short enough that a leaked value has a small window.
const SESSION_CREDENTIAL_TTL_MS = 60 * 60 * 1000;

function generateSecret(): string {
  return randomBytes(32).toString('base64url');
}

function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

// Firestore's Node client returns a Timestamp (toDate()/toMillis()) for
// timestamp fields, not a native Date -- same defensive handling already
// used by formatTimestamp() in routes/crypto.ts and firestore-registry.ts.
function toMillis(value: Date | { toMillis: () => number } | { toDate: () => Date }): number {
  if (value instanceof Date) return value.getTime();
  if (typeof (value as { toMillis?: () => number }).toMillis === 'function') {
    return (value as { toMillis: () => number }).toMillis();
  }
  if (typeof (value as { toDate?: () => Date }).toDate === 'function') {
    return (value as { toDate: () => Date }).toDate().getTime();
  }
  return new Date(value as unknown as string).getTime();
}

export interface ResolvedAnalystIdentity {
  tenantId: string;
  analystEmail: string;
}

export class AnalystAccessService {
  constructor(private readonly repo: AnalystAccessRepository) {}

  async createClaim(tenantId: string, analystEmail: string): Promise<string> {
    const claimToken = generateSecret();
    const expiresAt = new Date(Date.now() + CLAIM_EXPIRY_MS);
    await this.repo.createClaim(tenantId, analystEmail, hash(claimToken), expiresAt);
    return claimToken;
  }

  /**
   * Consumes a one-time claim token and issues a real API key. Returns null
   * if the token is unknown, expired, or already claimed -- never throws for
   * those cases, since they're expected outcomes (a re-clicked link, an
   * email scanner's prefetch), not failures.
   */
  async claim(claimToken: string): Promise<{ apiKey: string; analystEmail: string } | null> {
    const claimTokenHash = hash(claimToken);
    const record = await this.repo.getClaimByTokenHash(claimTokenHash);
    if (!record) {
      return null;
    }
    if (record.claimed_at) {
      logger.warn({ analystEmail: record.analyst_email }, 'Rejected already-claimed analyst claim token');
      return null;
    }
    if (toMillis(record.expires_at) < Date.now()) {
      logger.warn({ analystEmail: record.analyst_email }, 'Rejected expired analyst claim token');
      return null;
    }

    const apiKey = generateSecret();
    const claimed = await this.repo.claimAndIssueCredential(claimTokenHash, hash(apiKey));
    if (!claimed) {
      // Lost a race against a concurrent claim of the same token.
      return null;
    }

    logger.info({ tenantId: record.tenant_id, analystEmail: record.analyst_email }, 'Analyst claimed their Key Vault credential');
    return { apiKey, analystEmail: record.analyst_email };
  }

  async resolveCredential(presentedApiKey: string): Promise<ResolvedAnalystIdentity | null> {
    const record = await this.repo.resolveCredential(hash(presentedApiKey));
    if (!record || record.revoked_at) {
      return null;
    }
    // Only console-session credentials carry this -- a claim-link-issued
    // API key is durable until revoked, by design.
    if (record.credential_expires_at && toMillis(record.credential_expires_at) < Date.now()) {
      return null;
    }
    return { tenantId: record.tenant_id, analystEmail: record.analyst_email };
  }

  /**
   * Mints a short-lived credential on behalf of a person the console has
   * already authenticated (a real per-person session, not the static
   * shared-password fallback) -- no claim-link step, since there's no
   * external analyst to email a link to here. Reuses the exact same
   * resolution path as a claim-link credential (resolveCredential above),
   * so every route that already accepts an analyst credential accepts this
   * too with no further changes.
   */
  async mintSessionCredential(tenantId: string, analystEmail: string): Promise<{ credential: string; expiresAt: Date }> {
    const credential = generateSecret();
    const expiresAt = new Date(Date.now() + SESSION_CREDENTIAL_TTL_MS);
    await this.repo.createSessionCredential(tenantId, analystEmail, hash(credential), expiresAt);
    logger.info({ tenantId, analystEmail }, 'Minted console-session credential');
    return { credential, expiresAt };
  }
}

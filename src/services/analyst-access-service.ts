import { randomBytes, createHash } from 'crypto';
import { AnalystAccessRepository } from '../gcp/analyst-access-repository.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('analyst-access-service');

// One-time claim links expire after a week -- long enough for a customer's
// admin to forward it to a new hire, short enough that a stale unclaimed
// link isn't a standing credential-in-waiting.
const CLAIM_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

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
    return { tenantId: record.tenant_id, analystEmail: record.analyst_email };
  }
}

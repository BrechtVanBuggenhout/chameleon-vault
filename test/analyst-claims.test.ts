import { describe, expect, it } from '@jest/globals';
import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { registerRequestLogging } from '../src/middleware/request-logging.js';
import { AnalystAccessService } from '../src/services/analyst-access-service.js';
import { AnalystAccessRepository } from '../src/gcp/analyst-access-repository.js';
import { AnalystAccess } from '../src/types/analyst-access.js';
import { analystClaimsRoutes } from '../src/routes/analyst-claims.js';

// In-memory fake, same idea as pii-registry-declare.test.ts's FakeStore --
// exercises the real service against a simple store instead of Firestore.
class InMemoryAnalystAccessRepo implements Pick<AnalystAccessRepository, 'createClaim' | 'getClaimByTokenHash' | 'claimAndIssueCredential' | 'resolveCredential'> {
  private byTokenHash = new Map<string, AnalystAccess>();

  async createClaim(tenantId: string, analystEmail: string, claimTokenHash: string, expiresAt: Date): Promise<void> {
    this.byTokenHash.set(claimTokenHash, {
      claim_token_hash: claimTokenHash,
      tenant_id: tenantId,
      analyst_email: analystEmail,
      created_at: new Date(),
      expires_at: expiresAt,
    });
  }

  async getClaimByTokenHash(claimTokenHash: string): Promise<AnalystAccess | null> {
    return this.byTokenHash.get(claimTokenHash) ?? null;
  }

  async claimAndIssueCredential(claimTokenHash: string, credentialKeyHash: string): Promise<AnalystAccess | null> {
    const record = this.byTokenHash.get(claimTokenHash);
    if (!record || record.claimed_at) return null;
    const updated = { ...record, claimed_at: new Date(), credential_key_hash: credentialKeyHash };
    this.byTokenHash.set(claimTokenHash, updated);
    return updated;
  }

  async resolveCredential(credentialKeyHash: string): Promise<AnalystAccess | null> {
    for (const record of this.byTokenHash.values()) {
      if (record.credential_key_hash === credentialKeyHash) return record;
    }
    return null;
  }
}

async function buildApp() {
  const repo = new InMemoryAnalystAccessRepo();
  const analystAccessService = new AnalystAccessService(repo as unknown as AnalystAccessRepository);

  const app = Fastify({ logger: false });
  await app.register(rateLimit, { global: false });
  await registerRequestLogging(app);
  await app.register(analystClaimsRoutes, { analystAccessService });
  return { app, analystAccessService };
}

describe('analyst-claims routes', () => {
  it('creates one claim token per requested email', async () => {
    const { app } = await buildApp();

    const response = await app.inject({
      method: 'POST',
      url: '/admin/analyst-claims',
      payload: { analystEmails: ['a@example.com', 'b@example.com'] },
    });

    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.body);
    expect(body.claimTokens).toHaveLength(2);
    expect(body.claimTokens[0]).toEqual({ email: 'a@example.com', claimToken: expect.any(String) });
    expect(body.claimTokens[0].claimToken).not.toBe(body.claimTokens[1].claimToken);

    await app.close();
  });

  it('rejects claim creation with no emails', async () => {
    const { app } = await buildApp();

    const response = await app.inject({
      method: 'POST',
      url: '/admin/analyst-claims',
      payload: { analystEmails: [] },
    });

    expect(response.statusCode).toBe(400);
    await app.close();
  });

  it('lets a valid claim token be redeemed exactly once', async () => {
    const { app } = await buildApp();

    const createResponse = await app.inject({
      method: 'POST',
      url: '/admin/analyst-claims',
      payload: { analystEmails: ['a@example.com'] },
    });
    const { claimToken } = JSON.parse(createResponse.body).claimTokens[0];

    const firstClaim = await app.inject({ method: 'POST', url: `/admin/analyst-claims/${claimToken}/claim` });
    expect(firstClaim.statusCode).toBe(200);
    const firstBody = JSON.parse(firstClaim.body);
    expect(firstBody.analystEmail).toBe('a@example.com');
    expect(typeof firstBody.apiKey).toBe('string');

    const secondClaim = await app.inject({ method: 'POST', url: `/admin/analyst-claims/${claimToken}/claim` });
    expect(secondClaim.statusCode).toBe(410);

    await app.close();
  });

  it('rejects claiming an unknown token', async () => {
    const { app } = await buildApp();

    const response = await app.inject({
      method: 'POST',
      url: `/admin/analyst-claims/${'a'.repeat(43)}/claim`,
    });

    expect(response.statusCode).toBe(410);
    await app.close();
  });
});

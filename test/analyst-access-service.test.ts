import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { createHash } from 'crypto';
import { AnalystAccessService } from '../src/services/analyst-access-service.js';
import { AnalystAccessRepository } from '../src/gcp/analyst-access-repository.js';
import { AnalystAccess } from '../src/types/analyst-access.js';

function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

describe('AnalystAccessService', () => {
  let mockRepo: { [K in keyof AnalystAccessRepository]: jest.Mock };
  let service: AnalystAccessService;

  beforeEach(() => {
    mockRepo = {
      createClaim: jest.fn().mockResolvedValue(undefined),
      getClaimByTokenHash: jest.fn(),
      claimAndIssueCredential: jest.fn(),
      resolveCredential: jest.fn(),
      createSessionCredential: jest.fn().mockResolvedValue(undefined),
    } as any;
    service = new AnalystAccessService(mockRepo as unknown as AnalystAccessRepository);
  });

  describe('createClaim', () => {
    it('generates a random token, stores only its hash, and returns the raw token', async () => {
      const token = await service.createClaim('tenant-a', 'analyst@example.com');

      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(20);

      expect(mockRepo.createClaim).toHaveBeenCalledTimes(1);
      const [tenantId, analystEmail, storedHash, expiresAt] = mockRepo.createClaim.mock.calls[0];
      expect(tenantId).toBe('tenant-a');
      expect(analystEmail).toBe('analyst@example.com');
      expect(storedHash).toBe(hash(token));
      expect(storedHash).not.toBe(token);
      expect(expiresAt.getTime()).toBeGreaterThan(Date.now());

      // Not passed explicitly above -- defaults to 'analyst' for backward
      // compatibility with every call site that predates the role param.
      const [, , , , role] = mockRepo.createClaim.mock.calls[0];
      expect(role).toBe('analyst');
    });

    it('passes through an explicit auditor role', async () => {
      await service.createClaim('tenant-a', 'auditor@example.com', 'auditor');

      const [tenantId, auditorEmail, , , role] = mockRepo.createClaim.mock.calls[0];
      expect(tenantId).toBe('tenant-a');
      expect(auditorEmail).toBe('auditor@example.com');
      expect(role).toBe('auditor');
    });
  });

  describe('claim', () => {
    const baseRecord: AnalystAccess = {
      claim_token_hash: 'irrelevant-for-lookup', // service looks up by hash(token) it computes itself
      tenant_id: 'tenant-a',
      analyst_email: 'analyst@example.com',
      created_at: new Date(),
      expires_at: new Date(Date.now() + 60_000),
    };

    it('returns null when the token is unknown', async () => {
      mockRepo.getClaimByTokenHash.mockResolvedValue(null);
      const result = await service.claim('some-token');
      expect(result).toBeNull();
      expect(mockRepo.claimAndIssueCredential).not.toHaveBeenCalled();
    });

    it('returns null when the token was already claimed', async () => {
      mockRepo.getClaimByTokenHash.mockResolvedValue({ ...baseRecord, claimed_at: new Date() });
      const result = await service.claim('some-token');
      expect(result).toBeNull();
      expect(mockRepo.claimAndIssueCredential).not.toHaveBeenCalled();
    });

    it('returns null when the token has expired', async () => {
      mockRepo.getClaimByTokenHash.mockResolvedValue({ ...baseRecord, expires_at: new Date(Date.now() - 1000) });
      const result = await service.claim('some-token');
      expect(result).toBeNull();
      expect(mockRepo.claimAndIssueCredential).not.toHaveBeenCalled();
    });

    it('handles a Firestore Timestamp-shaped expires_at (toMillis), not just a native Date', async () => {
      mockRepo.getClaimByTokenHash.mockResolvedValue({
        ...baseRecord,
        expires_at: { toMillis: () => Date.now() - 1000 } as any,
      });
      const result = await service.claim('some-token');
      expect(result).toBeNull();
    });

    it('issues a real API key on a valid, unclaimed, unexpired token', async () => {
      mockRepo.getClaimByTokenHash.mockResolvedValue(baseRecord);
      mockRepo.claimAndIssueCredential.mockImplementation(async (_claimTokenHash: string, credentialKeyHash: string) => ({
        ...baseRecord,
        claimed_at: new Date(),
        credential_key_hash: credentialKeyHash,
      }));

      const result = await service.claim('some-token');

      expect(result).not.toBeNull();
      expect(result!.analystEmail).toBe('analyst@example.com');
      expect(result!.role).toBe('analyst');
      expect(typeof result!.apiKey).toBe('string');
      expect(result!.apiKey.length).toBeGreaterThan(20);

      const [claimTokenHashArg, credentialKeyHashArg] = mockRepo.claimAndIssueCredential.mock.calls[0];
      expect(claimTokenHashArg).toBe(hash('some-token'));
      expect(credentialKeyHashArg).toBe(hash(result!.apiKey));
    });

    it('returns null if claimAndIssueCredential loses a race (concurrent claim)', async () => {
      mockRepo.getClaimByTokenHash.mockResolvedValue(baseRecord);
      mockRepo.claimAndIssueCredential.mockResolvedValue(null);

      const result = await service.claim('some-token');
      expect(result).toBeNull();
    });

    it('carries an auditor-role claim through to the issued credential', async () => {
      const auditorRecord = { ...baseRecord, role: 'auditor' as const };
      mockRepo.getClaimByTokenHash.mockResolvedValue(auditorRecord);
      mockRepo.claimAndIssueCredential.mockImplementation(async (_claimTokenHash: string, credentialKeyHash: string) => ({
        ...auditorRecord,
        claimed_at: new Date(),
        credential_key_hash: credentialKeyHash,
      }));

      const result = await service.claim('some-token');
      expect(result!.role).toBe('auditor');
    });
  });

  describe('resolveCredential', () => {
    it('returns null when no credential matches', async () => {
      mockRepo.resolveCredential.mockResolvedValue(null);
      const result = await service.resolveCredential('some-api-key');
      expect(result).toBeNull();
    });

    it('returns null when the matching credential has been revoked', async () => {
      mockRepo.resolveCredential.mockResolvedValue({
        claim_token_hash: 'x',
        credential_key_hash: hash('some-api-key'),
        tenant_id: 'tenant-a',
        analyst_email: 'analyst@example.com',
        created_at: new Date(),
        expires_at: new Date(),
        claimed_at: new Date(),
        revoked_at: new Date(),
      });
      const result = await service.resolveCredential('some-api-key');
      expect(result).toBeNull();
    });

    it('resolves the tenant and analyst email for a valid, non-revoked credential', async () => {
      mockRepo.resolveCredential.mockResolvedValue({
        claim_token_hash: 'x',
        credential_key_hash: hash('some-api-key'),
        tenant_id: 'tenant-a',
        analyst_email: 'analyst@example.com',
        created_at: new Date(),
        expires_at: new Date(),
        claimed_at: new Date(),
      });

      const result = await service.resolveCredential('some-api-key');

      expect(result).toEqual({ tenantId: 'tenant-a', analystEmail: 'analyst@example.com', role: 'analyst' });
      expect(mockRepo.resolveCredential).toHaveBeenCalledWith(hash('some-api-key'));
    });

    it('returns null when a console-session credential has passed its credential_expires_at', async () => {
      mockRepo.resolveCredential.mockResolvedValue({
        claim_token_hash: hash('some-api-key'),
        credential_key_hash: hash('some-api-key'),
        tenant_id: 'tenant-a',
        analyst_email: 'analyst@example.com',
        created_at: new Date(),
        expires_at: new Date(),
        claimed_at: new Date(),
        source: 'console_session',
        credential_expires_at: new Date(Date.now() - 1000),
      });

      const result = await service.resolveCredential('some-api-key');
      expect(result).toBeNull();
    });

    it('resolves a console-session credential that has not yet expired', async () => {
      mockRepo.resolveCredential.mockResolvedValue({
        claim_token_hash: hash('some-api-key'),
        credential_key_hash: hash('some-api-key'),
        tenant_id: 'tenant-a',
        analyst_email: 'analyst@example.com',
        created_at: new Date(),
        expires_at: new Date(),
        claimed_at: new Date(),
        source: 'console_session',
        credential_expires_at: new Date(Date.now() + 60_000),
      });

      const result = await service.resolveCredential('some-api-key');
      expect(result).toEqual({ tenantId: 'tenant-a', analystEmail: 'analyst@example.com', role: 'analyst' });
    });

    it('handles a Firestore Timestamp-shaped credential_expires_at (toMillis), not just a native Date', async () => {
      mockRepo.resolveCredential.mockResolvedValue({
        claim_token_hash: hash('some-api-key'),
        credential_key_hash: hash('some-api-key'),
        tenant_id: 'tenant-a',
        analyst_email: 'analyst@example.com',
        created_at: new Date(),
        expires_at: new Date(),
        claimed_at: new Date(),
        source: 'console_session',
        credential_expires_at: { toMillis: () => Date.now() - 1000 } as any,
      });

      const result = await service.resolveCredential('some-api-key');
      expect(result).toBeNull();
    });
  });

  describe('mintSessionCredential', () => {
    it('generates a random credential, stores only its hash with an expiry, and returns the raw credential', async () => {
      const { credential, expiresAt } = await service.mintSessionCredential('tenant-a', 'person@example.com');

      expect(typeof credential).toBe('string');
      expect(credential.length).toBeGreaterThan(20);
      expect(expiresAt.getTime()).toBeGreaterThan(Date.now());

      expect(mockRepo.createSessionCredential).toHaveBeenCalledTimes(1);
      const [tenantId, analystEmail, storedHash, storedExpiresAt] = mockRepo.createSessionCredential.mock.calls[0];
      expect(tenantId).toBe('tenant-a');
      expect(analystEmail).toBe('person@example.com');
      expect(storedHash).toBe(hash(credential));
      expect(storedHash).not.toBe(credential);
      expect(storedExpiresAt).toBe(expiresAt);
    });
  });
});

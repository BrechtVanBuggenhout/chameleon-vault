import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { isExemptFromAuth, resolveAuth } from '../src/middleware/auth.js';
import { AnalystAccessService } from '../src/services/analyst-access-service.js';

const SHARED_KEY = 'the-shared-service-key';

describe('isExemptFromAuth', () => {
  it('exempts /health', () => {
    expect(isExemptFromAuth('/health')).toBe(true);
  });

  it('exempts the claim-consumption route for any token', () => {
    expect(isExemptFromAuth('/admin/analyst-claims/abcXYZ123-_/claim')).toBe(true);
  });

  it('does NOT exempt the claim-creation route (no token segment)', () => {
    expect(isExemptFromAuth('/admin/analyst-claims')).toBe(false);
  });

  it('does not exempt ordinary routes', () => {
    expect(isExemptFromAuth('/encrypt')).toBe(false);
    expect(isExemptFromAuth('/decrypt')).toBe(false);
    expect(isExemptFromAuth('/key/shred')).toBe(false);
  });

  it('exempts the decrypted-views batch-decrypt route -- BigQuery has no way to present VAULT_API_KEY, it self-authenticates via ID token instead', () => {
    expect(isExemptFromAuth('/internal/decrypted-views/batch-decrypt')).toBe(true);
  });

  it('does NOT exempt the decrypted-views management routes -- console-facing, still needs the shared key', () => {
    expect(isExemptFromAuth('/decrypted-views')).toBe(false);
    expect(isExemptFromAuth('/decrypted-views/some-view')).toBe(false);
  });

  it('exempts the public verification endpoints -- an outside auditor has no VAULT_API_KEY, and these carry no secret', () => {
    expect(isExemptFromAuth('/public-key')).toBe(true);
    expect(isExemptFromAuth('/.well-known/jwks.json')).toBe(true);
  });

  it('exempts certificate-chain-by-hash lookups for any hash -- only reachable by someone who already holds a real chained certificate', () => {
    expect(isExemptFromAuth('/certificate-chain/by-hash/abc123')).toBe(true);
    expect(isExemptFromAuth(`/certificate-chain/by-hash/${'f'.repeat(64)}`)).toBe(true);
  });

  it('does NOT exempt /certificate/:userId -- that is the internal lookup API, not the verification surface', () => {
    expect(isExemptFromAuth('/certificate/user123')).toBe(false);
  });

  it('does NOT exempt the certificate-chain collection route (no hash segment)', () => {
    expect(isExemptFromAuth('/certificate-chain/by-hash')).toBe(false);
    expect(isExemptFromAuth('/certificate-chain/by-hash/')).toBe(false);
  });
});

describe('resolveAuth', () => {
  let mockAnalystAccessService: { resolveCredential: jest.Mock };

  beforeEach(() => {
    mockAnalystAccessService = { resolveCredential: jest.fn() };
  });

  it('authorizes the shared key on any route, with no analyst identity attached -- and regardless of the tenant header, since it is deliberately tenant-unscoped', async () => {
    const result = await resolveAuth(
      '/key/shred',
      SHARED_KEY,
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'some-other-tenant'
    );
    expect(result).toEqual({ authorized: true });
    expect(mockAnalystAccessService.resolveCredential).not.toHaveBeenCalled();
  });

  it('rejects a key that matches neither the shared key nor any analyst credential', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue(null);
    const result = await resolveAuth(
      '/encrypt',
      'some-random-key',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: false });
  });

  it('accepts a valid analyst credential on /encrypt, attaching the analyst email and tenant', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/encrypt',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: true, analystEmail: 'a@example.com', tenantId: 'tenant-a' });
  });

  it('accepts a valid analyst credential on /decrypt', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/decrypt',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result.authorized).toBe(true);
  });

  it('rejects a valid analyst credential on any route other than /encrypt or /decrypt', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/key/shred',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    // Route isn't in the allowed set, so resolveCredential must never even be
    // consulted -- an analyst key should not be able to rotate/shred keys.
    expect(result).toEqual({ authorized: false });
    expect(mockAnalystAccessService.resolveCredential).not.toHaveBeenCalled();
  });

  it('rejects the admin analyst-claims creation route for an analyst credential', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/admin/analyst-claims',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: false });
  });

  it('accepts a valid analyst/console-session credential on POST /pii-registry/resources (declare)', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/pii-registry/resources',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: true, analystEmail: 'a@example.com', tenantId: 'tenant-a' });
  });

  it('accepts a valid credential on PUT/DELETE /pii-registry/resources/:resourceId', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/pii-registry/resources/bigquery%3Aproj.ds.table',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: true, analystEmail: 'a@example.com', tenantId: 'tenant-a' });
  });

  it('rejects a credential on the mark-synced sub-route -- machine-to-machine only, not an individual declare action', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/pii-registry/resources/some-resource/mark-synced',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: false });
    expect(mockAnalystAccessService.resolveCredential).not.toHaveBeenCalled();
  });

  it('rejects a credential on /pii-registry/sync-now -- machine-triggered, not an individual declare action', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/pii-registry/sync-now',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: false });
  });

  it('accepts a valid credential on POST /deletion-requests', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/deletion-requests',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: true, analystEmail: 'a@example.com', tenantId: 'tenant-a' });
  });

  it('rejects a credential on /admin/session-credentials -- only the console (shared key) mints these, never an analyst credential', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/admin/session-credentials',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: false });
  });

  it('accepts a valid auditor credential on /audit/key-status/:userId, attaching the auditor email and role', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({
      tenantId: 'tenant-a',
      analystEmail: 'auditor@example.com',
      role: 'auditor',
    });
    const result = await resolveAuth(
      '/audit/key-status/user-123',
      'auditor-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: true, analystEmail: 'auditor@example.com', role: 'auditor', tenantId: 'tenant-a' });
  });

  it('rejects a valid auditor credential on /encrypt -- an auditor can check erasure status, nothing else', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({
      tenantId: 'tenant-a',
      analystEmail: 'auditor@example.com',
      role: 'auditor',
    });
    const result = await resolveAuth(
      '/encrypt',
      'auditor-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: false });
  });

  it('rejects a valid analyst credential on /audit/key-status/:userId -- the two roles are not interchangeable', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({
      tenantId: 'tenant-a',
      analystEmail: 'a@example.com',
      role: 'analyst',
    });
    const result = await resolveAuth(
      '/audit/key-status/user-123',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: false });
  });

  it('rejects any credential on /admin/analyst-claims -- unreachable by either role, resolveCredential never consulted', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({
      tenantId: 'tenant-a',
      analystEmail: 'auditor@example.com',
      role: 'auditor',
    });
    const result = await resolveAuth(
      '/admin/analyst-claims',
      'auditor-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService,
      'tenant-a'
    );
    expect(result).toEqual({ authorized: false });
    expect(mockAnalystAccessService.resolveCredential).not.toHaveBeenCalled();
  });

  describe('tenant enforcement (found 2026-08-24)', () => {
    // Before this, a credential's own tenant_id was resolved but silently
    // discarded -- nothing ever compared it against the request's
    // x-tenant-id header, so a credential minted for one tenant could act
    // on any other tenant just by changing the header.
    it('rejects a valid, otherwise-allowed analyst credential when the request tenant does not match the credential\'s own tenant', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
      const result = await resolveAuth(
        '/encrypt',
        'analyst-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-b'
      );
      expect(result).toEqual({ authorized: false });
    });

    it('rejects on tenant mismatch even for the create-deletion-request route specifically', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
      const result = await resolveAuth(
        '/deletion-requests',
        'analyst-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-b'
      );
      expect(result).toEqual({ authorized: false });
    });

    it('accepts when the request tenant matches exactly (control case, not just "any mismatch rejected")', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
      const result = await resolveAuth(
        '/encrypt',
        'analyst-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result).toEqual({ authorized: true, analystEmail: 'a@example.com', tenantId: 'tenant-a' });
    });
  });

  describe('service credentials (external-system deletion trigger, found 2026-08-24)', () => {
    const serviceIdentity = { tenantId: 'tenant-a', analystEmail: 'partner:acme-crm', kind: 'service' as const };

    it('accepts a service credential on POST /deletion-requests (create)', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue(serviceIdentity);
      const result = await resolveAuth(
        '/deletion-requests',
        'service-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result).toEqual({
        authorized: true,
        analystEmail: 'partner:acme-crm',
        tenantId: 'tenant-a',
        credentialKind: 'service',
      });
    });

    it('accepts a service credential on GET /deletion-requests/:id', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue(serviceIdentity);
      const result = await resolveAuth(
        '/deletion-requests/del-123',
        'service-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result.authorized).toBe(true);
    });

    it('accepts a service credential on POST /deletion-requests/:id/advance', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue(serviceIdentity);
      const result = await resolveAuth(
        '/deletion-requests/del-123/advance',
        'service-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result.authorized).toBe(true);
    });

    it('accepts a service credential on GET /certificate/:userId', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue(serviceIdentity);
      const result = await resolveAuth(
        '/certificate/user-123',
        'service-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result.authorized).toBe(true);
    });

    it('rejects a service credential on /encrypt -- deletion-triggering only, no PII read access', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue(serviceIdentity);
      const result = await resolveAuth(
        '/encrypt',
        'service-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result).toEqual({ authorized: false });
    });

    it('rejects a service credential on /decrypt', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue(serviceIdentity);
      const result = await resolveAuth(
        '/decrypt',
        'service-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result).toEqual({ authorized: false });
    });

    it('rejects a service credential on POST /pii-registry/resources -- no reason for a deletion-trigger integration to declare PII', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue(serviceIdentity);
      const result = await resolveAuth(
        '/pii-registry/resources',
        'service-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result).toEqual({ authorized: false });
    });

    it('rejects an ORDINARY analyst credential on GET /certificate/:userId -- service-only path, even though the route pattern would otherwise match', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
      const result = await resolveAuth(
        '/certificate/user-123',
        'analyst-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result).toEqual({ authorized: false });
    });

    it('rejects an ordinary analyst credential on POST /deletion-requests/:id/advance -- analysts can create but never advance', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
      const result = await resolveAuth(
        '/deletion-requests/del-123/advance',
        'analyst-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result).toEqual({ authorized: false });
    });

    it('still enforces tenant match for a service credential', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue(serviceIdentity);
      const result = await resolveAuth(
        '/deletion-requests',
        'service-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-b'
      );
      expect(result).toEqual({ authorized: false });
    });

    it('does not attach credentialKind for an ordinary analyst credential', async () => {
      mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
      const result = await resolveAuth(
        '/deletion-requests',
        'analyst-key-value',
        SHARED_KEY,
        mockAnalystAccessService as unknown as AnalystAccessService,
        'tenant-a'
      );
      expect(result.credentialKind).toBeUndefined();
    });
  });
});

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
});

describe('resolveAuth', () => {
  let mockAnalystAccessService: { resolveCredential: jest.Mock };

  beforeEach(() => {
    mockAnalystAccessService = { resolveCredential: jest.fn() };
  });

  it('authorizes the shared key on any route, with no analyst identity attached', async () => {
    const result = await resolveAuth(
      '/key/shred',
      SHARED_KEY,
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService
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
      mockAnalystAccessService as unknown as AnalystAccessService
    );
    expect(result).toEqual({ authorized: false });
  });

  it('accepts a valid analyst credential on /encrypt, attaching the analyst email', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/encrypt',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService
    );
    expect(result).toEqual({ authorized: true, analystEmail: 'a@example.com' });
  });

  it('accepts a valid analyst credential on /decrypt', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/decrypt',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService
    );
    expect(result.authorized).toBe(true);
  });

  it('rejects a valid analyst credential on any route other than /encrypt or /decrypt', async () => {
    mockAnalystAccessService.resolveCredential.mockResolvedValue({ tenantId: 'tenant-a', analystEmail: 'a@example.com' });
    const result = await resolveAuth(
      '/key/shred',
      'analyst-key-value',
      SHARED_KEY,
      mockAnalystAccessService as unknown as AnalystAccessService
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
      mockAnalystAccessService as unknown as AnalystAccessService
    );
    expect(result).toEqual({ authorized: false });
  });
});

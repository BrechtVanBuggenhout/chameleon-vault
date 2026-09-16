import * as crypto from 'crypto';
import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import type { RekorLogEntryInfo } from '../src/gcp/rekor-client.js';

const mockGet = jest.fn();
await jest.unstable_mockModule('axios', () => ({
  default: { get: mockGet },
}));

const { verifyRekorEntry } = await import('../src/crypto/rekor-verify.js');

function digestOf(certificateHash: string, previousCertificateHash: string | null): string {
  return crypto.createHash('sha256').update(JSON.stringify({ certificateHash, previousCertificateHash })).digest('hex');
}

function entryResponse(hashValue: string, hashAlgorithm = 'sha256'): { status: number; data: Record<string, { body: string }> } {
  const body = Buffer.from(
    JSON.stringify({
      kind: 'hashedrekord',
      apiVersion: '0.0.1',
      spec: { signature: { content: 'sig', publicKey: { content: 'pk' } }, data: { hash: { algorithm: hashAlgorithm, value: hashValue } } },
    })
  ).toString('base64');
  return { status: 200, data: { 'entry-uuid-1': { body, logIndex: 42 } } };
}

describe('verifyRekorEntry', () => {
  beforeEach(() => {
    mockGet.mockReset();
  });

  const publishedEntry: RekorLogEntryInfo = {
    status: 'PUBLISHED',
    entryUuid: 'entry-uuid-1',
    logIndex: 42,
    rekorUrl: 'https://rekor.sigstore.dev',
    attemptedAt: '2026-09-01T00:00:00.000Z',
  };

  it('returns ABSENT when no rekorEntry was stored', async () => {
    const result = await verifyRekorEntry('cert-hash', null, undefined);
    expect(result).toEqual({ outcome: 'ABSENT' });
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('returns RECORDED_FAILURE without a network call when the stored status is FAILED', async () => {
    const failed: RekorLogEntryInfo = { status: 'FAILED', rekorUrl: 'https://rekor.sigstore.dev', attemptedAt: 'x', error: 'HTTP 500' };
    const result = await verifyRekorEntry('cert-hash', null, failed);
    expect(result).toEqual({ outcome: 'RECORDED_FAILURE' });
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('returns INVALID when status is PUBLISHED but no entryUuid was ever stored', async () => {
    const noUuid: RekorLogEntryInfo = { status: 'PUBLISHED', rekorUrl: 'https://rekor.sigstore.dev', attemptedAt: 'x' };
    const result = await verifyRekorEntry('cert-hash', null, noUuid);
    expect(result.outcome).toBe('INVALID');
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('VALID: fetches the entry live and confirms its recorded hash matches the certificate', async () => {
    const expectedDigest = digestOf('cert-hash', 'prev-hash');
    mockGet.mockResolvedValue(entryResponse(expectedDigest));

    const result = await verifyRekorEntry('cert-hash', 'prev-hash', publishedEntry);

    expect(mockGet).toHaveBeenCalledWith(
      'https://rekor.sigstore.dev/api/v1/log/entries/entry-uuid-1',
      expect.objectContaining({ timeout: expect.any(Number) })
    );
    expect(result).toEqual({ outcome: 'VALID', entryUuid: 'entry-uuid-1', logIndex: 42, rekorUrl: 'https://rekor.sigstore.dev' });
  });

  it('VALID: handles previousCertificateHash being null (genesis certificate)', async () => {
    const expectedDigest = digestOf('cert-hash', null);
    mockGet.mockResolvedValue(entryResponse(expectedDigest));

    const result = await verifyRekorEntry('cert-hash', null, publishedEntry);

    expect(result.outcome).toBe('VALID');
  });

  it('INVALID: the log entry exists but records a different hash than this certificate', async () => {
    mockGet.mockResolvedValue(entryResponse(digestOf('some-other-cert-hash', null)));

    const result = await verifyRekorEntry('cert-hash', 'prev-hash', publishedEntry);

    expect(result.outcome).toBe('INVALID');
    if (result.outcome === 'INVALID') {
      expect(result.reason).toMatch(/does not match/);
    }
  });

  it('INVALID: Rekor returns a non-200 status (entry not found / log unavailable)', async () => {
    mockGet.mockResolvedValue({ status: 404, data: {} });

    const result = await verifyRekorEntry('cert-hash', null, publishedEntry);

    expect(result.outcome).toBe('INVALID');
    if (result.outcome === 'INVALID') {
      expect(result.reason).toContain('HTTP 404');
    }
  });

  it('INVALID: entry body is missing spec.data.hash entirely', async () => {
    const body = Buffer.from(JSON.stringify({ kind: 'hashedrekord', spec: {} })).toString('base64');
    mockGet.mockResolvedValue({ status: 200, data: { 'entry-uuid-1': { body } } });

    const result = await verifyRekorEntry('cert-hash', null, publishedEntry);

    expect(result.outcome).toBe('INVALID');
  });

  it('INVALID: entry records a hash under an unexpected algorithm', async () => {
    mockGet.mockResolvedValue(entryResponse(digestOf('cert-hash', null), 'sha1'));

    const result = await verifyRekorEntry('cert-hash', null, publishedEntry);

    expect(result.outcome).toBe('INVALID');
    if (result.outcome === 'INVALID') {
      expect(result.reason).toContain('sha1');
    }
  });

  it('INVALID, never throws, when the request itself throws (network error)', async () => {
    mockGet.mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await verifyRekorEntry('cert-hash', null, publishedEntry);

    expect(result).toEqual({ outcome: 'INVALID', reason: 'ECONNREFUSED' });
  });
});

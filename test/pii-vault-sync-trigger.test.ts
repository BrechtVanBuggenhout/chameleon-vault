import { jest, describe, it, expect, beforeEach } from '@jest/globals';

const mockRequest = jest.fn();
const mockIdTokenRequest = jest.fn();
const mockGetClient = jest.fn().mockImplementation(async () => ({ request: mockRequest }));
const mockGetIdTokenClient = jest.fn().mockImplementation(async () => ({ request: mockIdTokenRequest }));
const mockGoogleAuth = jest.fn().mockImplementation(() => ({
  getClient: mockGetClient,
  getIdTokenClient: mockGetIdTokenClient,
}));

await jest.unstable_mockModule('google-auth-library', () => ({
  GoogleAuth: mockGoogleAuth,
}));

await jest.unstable_mockModule('../src/logging/index.js', () => ({
  createLogger: () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }),
}));

const { PiiVaultSyncTrigger } = await import('../src/gcp/pii-vault-sync-trigger.js');

describe('PiiVaultSyncTrigger', () => {
  beforeEach(() => {
    mockRequest.mockReset();
    mockIdTokenRequest.mockReset();
    mockGetIdTokenClient.mockClear();
  });

  it('resolves the worker URL via the Cloud Run Admin API, then mints an OIDC token scoped to it', async () => {
    mockRequest.mockResolvedValueOnce({ data: { uri: 'https://pii-ingestor-worker-abc123.a.run.app' } });
    mockIdTokenRequest.mockResolvedValueOnce({
      data: { status: 'ok', resources_queued: 1, chunks_queued: 3, errors: [] },
    });
    const trigger = new PiiVaultSyncTrigger('proj', 'us-central1', 'chameleon-pii-ingestor-worker-dev');

    const result = await trigger.trigger();

    // Admin API lookup uses the plain, dependency-free config -- never a
    // literal URL, since that would require a Terraform reference this
    // repo can't take (see the class docstring for the cycle it avoids).
    expect(mockRequest).toHaveBeenCalledWith({
      url: 'https://run.googleapis.com/v2/projects/proj/locations/us-central1/services/chameleon-pii-ingestor-worker-dev',
    });
    // The resolved URL, not the service name, becomes the OIDC audience --
    // that's what makes the minted token valid for this Cloud Run revision.
    expect(mockGetIdTokenClient).toHaveBeenCalledWith('https://pii-ingestor-worker-abc123.a.run.app');
    // Always a full scan, never the daily job's incremental path -- see
    // the trigger() docstring.
    expect(mockIdTokenRequest).toHaveBeenCalledWith({
      url: 'https://pii-ingestor-worker-abc123.a.run.app/api/v1/pii-vault-sync',
      method: 'POST',
      data: { force_full_scan: true },
    });
    expect(result).toEqual({ status: 'ok', resources_queued: 1, chunks_queued: 3, errors: [] });
  });

  it('caches the resolved URL instead of re-querying the Admin API on every trigger', async () => {
    mockRequest.mockResolvedValueOnce({ data: { uri: 'https://pii-ingestor-worker-abc123.a.run.app' } });
    mockIdTokenRequest.mockResolvedValue({
      data: { status: 'ok', resources_queued: 0, chunks_queued: 0, errors: [] },
    });
    const trigger = new PiiVaultSyncTrigger('proj', 'us-central1', 'worker');

    await trigger.trigger();
    await trigger.trigger();

    expect(mockRequest).toHaveBeenCalledTimes(1);
    expect(mockIdTokenRequest).toHaveBeenCalledTimes(2);
  });

  it('throws when the Admin API returns no uri, instead of silently calling an empty URL', async () => {
    mockRequest.mockResolvedValueOnce({ data: {} });
    const trigger = new PiiVaultSyncTrigger('proj', 'us-central1', 'worker');

    await expect(trigger.trigger()).rejects.toThrow('no uri');
  });

  it('propagates a failure from the worker instead of swallowing it', async () => {
    mockRequest.mockResolvedValueOnce({ data: { uri: 'https://pii-ingestor-worker-abc123.a.run.app' } });
    mockIdTokenRequest.mockRejectedValueOnce(new Error('403: Permission denied'));
    const trigger = new PiiVaultSyncTrigger('proj', 'us-central1', 'worker');

    await expect(trigger.trigger()).rejects.toThrow('403: Permission denied');
  });
});

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

const { SourceStalenessChecker } = await import('../src/gcp/source-staleness-checker.js');

describe('SourceStalenessChecker', () => {
  beforeEach(() => {
    mockRequest.mockReset();
    mockIdTokenRequest.mockReset();
    mockGetIdTokenClient.mockClear();
  });

  it('resolves the worker URL via the Cloud Run Admin API, then proxies the staleness check', async () => {
    mockRequest.mockResolvedValueOnce({ data: { uri: 'https://pii-ingestor-worker-abc123.a.run.app' } });
    mockIdTokenRequest.mockResolvedValueOnce({
      data: { status: 'ok', results: { 'key-vault': { status: 'current', builtSha: 'a', latestSha: 'a' } } },
    });
    const checker = new SourceStalenessChecker('proj', 'us-central1', 'chameleon-pii-ingestor-worker-dev');

    const result = await checker.check();

    expect(mockRequest).toHaveBeenCalledWith({
      url: 'https://run.googleapis.com/v2/projects/proj/locations/us-central1/services/chameleon-pii-ingestor-worker-dev',
    });
    expect(mockGetIdTokenClient).toHaveBeenCalledWith('https://pii-ingestor-worker-abc123.a.run.app');
    expect(mockIdTokenRequest).toHaveBeenCalledWith({
      url: 'https://pii-ingestor-worker-abc123.a.run.app/api/v1/source-staleness-check',
      method: 'POST',
    });
    expect(result).toEqual({ status: 'ok', results: { 'key-vault': { status: 'current', builtSha: 'a', latestSha: 'a' } } });
  });

  it('passes through platformVersion untouched, regardless of the self-build results shape', async () => {
    mockRequest.mockResolvedValueOnce({ data: { uri: 'https://pii-ingestor-worker-abc123.a.run.app' } });
    mockIdTokenRequest.mockResolvedValueOnce({
      data: {
        status: 'not_applicable',
        platformVersion: { status: 'stale', currentVersion: 'v2026.08.10', latestVersion: 'v2026.08.20' },
      },
    });
    const checker = new SourceStalenessChecker('proj', 'us-central1', 'worker');

    const result = await checker.check();

    expect(result.platformVersion).toEqual({
      status: 'stale',
      currentVersion: 'v2026.08.10',
      latestVersion: 'v2026.08.20',
    });
  });

  it('caches the resolved URL instead of re-querying the Admin API on every check', async () => {
    mockRequest.mockResolvedValueOnce({ data: { uri: 'https://pii-ingestor-worker-abc123.a.run.app' } });
    mockIdTokenRequest.mockResolvedValue({ data: { status: 'ok', results: {} } });
    const checker = new SourceStalenessChecker('proj', 'us-central1', 'worker');

    await checker.check();
    await checker.check();

    expect(mockRequest).toHaveBeenCalledTimes(1);
    expect(mockIdTokenRequest).toHaveBeenCalledTimes(2);
  });

  it('throws when the Admin API returns no uri, instead of silently calling an empty URL', async () => {
    mockRequest.mockResolvedValueOnce({ data: {} });
    const checker = new SourceStalenessChecker('proj', 'us-central1', 'worker');

    await expect(checker.check()).rejects.toThrow('no uri');
  });

  it('propagates a failure from the worker instead of swallowing it', async () => {
    mockRequest.mockResolvedValueOnce({ data: { uri: 'https://pii-ingestor-worker-abc123.a.run.app' } });
    mockIdTokenRequest.mockRejectedValueOnce(new Error('403: Permission denied'));
    const checker = new SourceStalenessChecker('proj', 'us-central1', 'worker');

    await expect(checker.check()).rejects.toThrow('403: Permission denied');
  });
});

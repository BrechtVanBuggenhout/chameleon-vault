import { jest, describe, it, expect, beforeEach, afterAll } from '@jest/globals';
const mockWrite = jest.fn().mockResolvedValue(undefined);
const mockEntry = jest.fn((metadata, data) => ({ metadata, data }));
const mockLog = jest.fn(() => ({
  entry: mockEntry,
  write: mockWrite,
}));
const mockLogging = jest.fn(() => ({
  log: mockLog,
}));

await jest.unstable_mockModule('@google-cloud/logging', () => ({
  Logging: mockLogging,
}));

const { mapPinoLevelToCloudSeverity, writeLog } = await import('../src/logging/cloud-logging.js');

describe('Cloud Logging export', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalProjectId = process.env.GCP_PROJECT_ID;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.GCP_PROJECT_ID = 'test-project';
  });

  afterAll(() => {
    process.env.NODE_ENV = originalNodeEnv;
    process.env.GCP_PROJECT_ID = originalProjectId;
  });

  it('maps Pino levels to Cloud Logging severities', () => {
    expect(mapPinoLevelToCloudSeverity(10)).toBe('DEBUG');
    expect(mapPinoLevelToCloudSeverity(20)).toBe('DEBUG');
    expect(mapPinoLevelToCloudSeverity(30)).toBe('INFO');
    expect(mapPinoLevelToCloudSeverity(40)).toBe('WARNING');
    expect(mapPinoLevelToCloudSeverity(50)).toBe('ERROR');
    expect(mapPinoLevelToCloudSeverity(60)).toBe('CRITICAL');
    expect(mapPinoLevelToCloudSeverity(999)).toBe('DEFAULT');
  });

  it('does not export logs outside production', async () => {
    process.env.NODE_ENV = 'development';

    await writeLog({
      severity: 'INFO',
      message: 'local log',
      data: { module: 'test' },
    });

    expect(mockLogging).not.toHaveBeenCalled();
    expect(mockWrite).not.toHaveBeenCalled();
  });

  it('writes structured entries to Cloud Logging in production', async () => {
    process.env.NODE_ENV = 'production';

    await writeLog({
      severity: 'NOTICE',
      message: 'key generated',
      labels: { operation: 'KEY_GENERATE' },
      data: {
        module: 'crypto-routes',
        correlationId: 'corr-123',
        userId: 'user123',
      },
    });

    expect(mockLogging).toHaveBeenCalledWith({ projectId: 'test-project' });
    expect(mockLog).toHaveBeenCalledWith('chameleon-key-vault');
    expect(mockEntry).toHaveBeenCalledWith(
      {
        severity: 'NOTICE',
        labels: { operation: 'KEY_GENERATE' },
        sourceLocation: undefined,
      },
      {
        message: 'key generated',
        module: 'crypto-routes',
        correlationId: 'corr-123',
        userId: 'user123',
      }
    );
    expect(mockWrite).toHaveBeenCalledWith({
      metadata: {
        severity: 'NOTICE',
        labels: { operation: 'KEY_GENERATE' },
        sourceLocation: undefined,
      },
      data: {
        message: 'key generated',
        module: 'crypto-routes',
        correlationId: 'corr-123',
        userId: 'user123',
      },
    });
  });
});

import { jest, describe, it, expect, beforeEach, afterAll } from '@jest/globals';
const mockWriteLog = jest.fn().mockResolvedValue(undefined);
const mockMapPinoLevelToCloudSeverity = jest.fn((level: number) => {
  if (level >= 60) return 'CRITICAL';
  if (level >= 50) return 'ERROR';
  if (level >= 40) return 'WARNING';
  return 'INFO';
});

await jest.unstable_mockModule('../src/logging/cloud-logging.js', () => ({
  mapPinoLevelToCloudSeverity: mockMapPinoLevelToCloudSeverity,
  writeLog: mockWriteLog,
}));

await jest.unstable_mockModule('../src/config/env.js', () => ({
  getRequiredEnv: jest.fn((_key: string) => {
    return 'mock-value'; // Just return a value, as logger doesn't use specific env vars from here
  }),
}));

describe('Pino logger Cloud Logging hook', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalLogLevel = process.env.LOG_LEVEL;

  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    process.env.NODE_ENV = 'production';
    process.env.LOG_LEVEL = 'debug';
  });

  afterAll(() => {
    process.env.NODE_ENV = originalNodeEnv;
    process.env.LOG_LEVEL = originalLogLevel;
  });

  it('exports production info logs with structured data', async () => {
    const { createLogger } = await import('../src/logging/index.js');
    const logger = createLogger('logger-export-test');

    logger.info({ correlationId: 'corr-123', operation: 'HEALTH_CHECK' }, 'Health check completed');

    expect(mockMapPinoLevelToCloudSeverity).toHaveBeenCalledWith(30);
    expect(mockWriteLog).toHaveBeenCalledWith(
      {
        severity: 'INFO',
        message: 'Health check completed',
        data: {
          correlationId: 'corr-123',
          operation: 'HEALTH_CHECK',
        },
        timestamp: expect.any(Date),
      },
      'chameleon-key-vault'
    );
  });

  it('normalizes string-only production log calls', async () => {
    const { createLogger } = await import('../src/logging/index.js');
    const logger = createLogger('logger-export-test');

    logger.warn('String only warning');

    expect(mockWriteLog).toHaveBeenCalledWith(
      {
        severity: 'WARNING',
        message: 'String only warning',
        data: {},
        timestamp: expect.any(Date),
      },
      'chameleon-key-vault'
    );
  });
});

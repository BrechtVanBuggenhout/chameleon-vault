import { jest, describe, it, expect, beforeEach } from '@jest/globals';

// snowflake-sdk is callback-based: createConnection().connect(cb), then .execute({ complete: cb }).
// mockRows is swapped per-test to drive queryRegistry() vs queryLineage() responses in order.
let mockRowsQueue: Record<string, unknown>[][] = [];

const mockExecute = jest.fn((options: { complete: (err: unknown, stmt: unknown, rows: unknown) => void }) => {
  const rows = mockRowsQueue.shift() ?? [];
  options.complete(undefined, {}, rows);
});

const mockConnect = jest.fn((cb: (err: unknown, conn: unknown) => void) => {
  cb(undefined, { execute: mockExecute });
});

const mockCreateConnection = jest.fn(() => ({
  connect: mockConnect,
  execute: mockExecute,
}));

await jest.unstable_mockModule('snowflake-sdk', () => ({
  default: { createConnection: mockCreateConnection },
  createConnection: mockCreateConnection,
}));

await jest.unstable_mockModule('../src/logging/index.js', () => ({
  createLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }),
}));

const { SnowflakePiiRegistryRepository } = await import('../src/snowflake/pii-registry-repository.js');

const connectionOptions = {
  account: 'RCXDLDA-TH87971',
  username: 'BVANBUGG',
  password: 'test-password',
  role: 'ACCOUNTADMIN',
  warehouse: 'COMPUTE_WH',
  database: 'CHAMELEON_DEV',
  schema: 'CHAMELEON_DEV',
};

describe('SnowflakePiiRegistryRepository', () => {
  beforeEach(() => {
    mockRowsQueue = [];
    mockExecute.mockClear();
    mockConnect.mockClear();
    mockCreateConnection.mockClear();
  });

  it('lowercases uppercase Snowflake result columns before assembling entries', async () => {
    // Snowflake uppercases unquoted identifiers, so a real driver would return
    // keys like RESOURCE_ID/MODEL_NAME rather than the lowercase names the
    // shared assemblePiiRegistryEntries() expects.
    mockRowsQueue = [
      [
        {
          RESOURCE_ID: 'snowflake:CHAMELEON_DEV.CHAMELEON_DEV.stg_users',
          MODEL_NAME: 'stg_users',
          SYSTEM: 'snowflake',
          RESOURCE_LAYER: 'STAGING',
          OWNER: 'dbt',
          FIELD_NAME: 'user_id',
          CLASSIFICATION: 'SYSTEM_IDENTIFIER',
          HANDLING: 'HASH_SURROGATE',
          CONFIDENCE: 'DECLARED',
          DETECTION_METHOD: 'DECLARED',
          REQUIRED_IN_MART: false,
          REGISTRY_VERSION: '2026-07-18',
        },
      ],
      [], // lineage query
    ];

    const repo = new SnowflakePiiRegistryRepository(connectionOptions);
    const entries = await repo.loadEntries();

    expect(entries).toHaveLength(1);
    expect(entries[0].resourceId).toBe('snowflake:CHAMELEON_DEV.CHAMELEON_DEV.stg_users');
    expect(entries[0].piiFields).toEqual([
      expect.objectContaining({ name: 'user_id', classification: 'SYSTEM_IDENTIFIER' }),
    ]);
  });

  it('returns an empty registry and swallows errors when the lineage table is missing', async () => {
    mockRowsQueue = [[]];
    mockExecute.mockImplementationOnce((options: { complete: (err: unknown, stmt: unknown, rows: unknown) => void }) => {
      options.complete(undefined, {}, []);
    });
    mockExecute.mockImplementationOnce((options: { complete: (err: unknown, stmt: unknown, rows: unknown) => void }) => {
      options.complete(new Error('Table PII_FIELD_LINEAGE does not exist'), {}, undefined);
    });

    const repo = new SnowflakePiiRegistryRepository(connectionOptions);
    const entries = await repo.loadEntries();

    expect(entries).toEqual([]);
  });

  it('reuses a single connection across the registry and lineage queries', async () => {
    mockRowsQueue = [[], []];
    const repo = new SnowflakePiiRegistryRepository(connectionOptions);
    await repo.loadEntries();

    expect(mockCreateConnection).toHaveBeenCalledTimes(1);
    expect(mockCreateConnection).toHaveBeenCalledWith(expect.objectContaining({ account: connectionOptions.account }));
  });
});

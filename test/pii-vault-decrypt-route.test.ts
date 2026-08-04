import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import Fastify from 'fastify';
import { ChameleonAesGcm } from '../src/crypto/chameleon-aes-gcm.js';
import { piiVaultDecryptRoutes } from '../src/routes/pii-vault-decrypt.js';

const ROUTE_PATH = '/pii-vault/decrypt';

const mockGetKeyForUser = jest.fn(async (userId: string) => {
  if (userId === 'shredded-user') return null;
  if (userId === 'known-user') {
    return { encryptedDek: Buffer.from('wrapped-dek'), activeDekId: 'v1', encryptionVersion: 'v1' };
  }
  return null;
});
const fakeFirestoreRegistry = { getKeyForUser: mockGetKeyForUser } as any;

const TEST_DEK = Buffer.alloc(32, 7);
const mockDecryptDataEncryptionKey = jest.fn(async () => TEST_DEK);
const fakeKmsClient = { decryptDataEncryptionKey: mockDecryptDataEncryptionKey } as any;

const mockFindCiphertext = jest.fn();
const fakePiiVaultLookup = { findCiphertext: mockFindCiphertext };

const mockRecordEvent = jest.fn(async () => 'event-id');
const fakeLineageRepository = { recordEvent: mockRecordEvent } as any;

function buildApp() {
  return Fastify();
}

async function registerRoute(app: ReturnType<typeof Fastify>) {
  await app.register(piiVaultDecryptRoutes, {
    piiVaultLookup: fakePiiVaultLookup,
    firestoreRegistry: fakeFirestoreRegistry,
    dekKmsClient: fakeKmsClient,
    lineageRepository: fakeLineageRepository,
  });
}

describe('POST /pii-vault/decrypt', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('requires userId, resourceId, and fieldName', async () => {
    const app = buildApp();
    await registerRoute(app);

    const response = await app.inject({
      method: 'POST',
      url: ROUTE_PATH,
      payload: { userId: 'known-user' },
    });

    expect(response.statusCode).toBe(400);
    expect(mockFindCiphertext).not.toHaveBeenCalled();
  });

  it('returns { value: null } for a field with no synced row, without leaking why', async () => {
    mockFindCiphertext.mockResolvedValue(null);
    const app = buildApp();
    await registerRoute(app);

    const response = await app.inject({
      method: 'POST',
      url: ROUTE_PATH,
      headers: { 'x-tenant-id': 'tenant-a' },
      payload: { userId: 'known-user', resourceId: 'bigquery:proj.ds.raw_users', fieldName: 'email' },
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ value: null });
    expect(mockFindCiphertext).toHaveBeenCalledWith({
      tenantId: 'tenant-a',
      userId: 'known-user',
      resourceId: 'bigquery:proj.ds.raw_users',
      fieldName: 'email',
    });
  });

  it('returns { value: null } for a shredded user rather than an error', async () => {
    const { ivB64, ciphertextB64 } = ChameleonAesGcm.encrypt('jane@example.com', 'shredded-user', TEST_DEK);
    mockFindCiphertext.mockResolvedValue(`v1:${ivB64}:${ciphertextB64}`);
    const app = buildApp();
    await registerRoute(app);

    const response = await app.inject({
      method: 'POST',
      url: ROUTE_PATH,
      payload: { userId: 'shredded-user', resourceId: 'bigquery:proj.ds.raw_users', fieldName: 'email' },
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ value: null });
  });

  it('decrypts and returns the real plaintext value', async () => {
    const { ivB64, ciphertextB64 } = ChameleonAesGcm.encrypt('jane@example.com', 'known-user', TEST_DEK);
    mockFindCiphertext.mockResolvedValue(`v1:${ivB64}:${ciphertextB64}`);
    const app = buildApp();
    await registerRoute(app);

    const response = await app.inject({
      method: 'POST',
      url: ROUTE_PATH,
      payload: { userId: 'known-user', resourceId: 'bigquery:proj.ds.raw_users', fieldName: 'email' },
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ value: 'jane@example.com' });
  });

  it('records an audit event without ever including the plaintext value', async () => {
    const { ivB64, ciphertextB64 } = ChameleonAesGcm.encrypt('jane@example.com', 'known-user', TEST_DEK);
    mockFindCiphertext.mockResolvedValue(`v1:${ivB64}:${ciphertextB64}`);
    const app = buildApp();
    await registerRoute(app);

    await app.inject({
      method: 'POST',
      url: ROUTE_PATH,
      payload: { userId: 'known-user', resourceId: 'bigquery:proj.ds.raw_users', fieldName: 'email' },
    });

    expect(mockRecordEvent).toHaveBeenCalledTimes(1);
    const [event] = mockRecordEvent.mock.calls[0] as [any];
    expect(event.eventType).toBe('AD_HOC_DECRYPT_PERFORMED');
    expect(event.userId).toBe('known-user');
    expect(event.context.found).toBe(true);
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain('jane@example.com');
  });

  it('returns 500 (not a silent null) when the pii_vault lookup itself fails', async () => {
    mockFindCiphertext.mockRejectedValue(new Error('BigQuery unavailable'));
    const app = buildApp();
    await registerRoute(app);

    const response = await app.inject({
      method: 'POST',
      url: ROUTE_PATH,
      payload: { userId: 'known-user', resourceId: 'bigquery:proj.ds.raw_users', fieldName: 'email' },
    });

    expect(response.statusCode).toBe(500);
    expect(mockRecordEvent).not.toHaveBeenCalled();
  });
});

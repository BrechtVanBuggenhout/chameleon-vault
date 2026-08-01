import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { ChameleonAesGcm } from '../src/crypto/chameleon-aes-gcm.js';

const ALLOWED_SA = 'connection-sa@proj.iam.gserviceaccount.com';
// Fastify's inject() defaults the Host header to this when none is passed --
// the route derives its expected audience from request.hostname, so this is
// what verifyIdToken should be called with unless a test overrides the host.
const DEFAULT_HOST = 'localhost:80';

const mockVerifyIdToken = jest.fn();
await jest.unstable_mockModule('google-auth-library', () => ({
  OAuth2Client: class {
    verifyIdToken = mockVerifyIdToken;
  },
}));

const { default: Fastify } = await import('fastify');
const { decryptedViewsDecryptRoutes } = await import('../src/routes/decrypted-views-decrypt.js');

// Mirrors the real DEK/ChameleonAesGcm flow closely enough to exercise the
// route's own logic without re-testing chameleon-aes-gcm.test.ts's already-
// covered decrypt internals: a "shredded" user has no encryptedDek (matches
// firestore-registry.ts's real getKeyForUser behavior on a shredded key).
const mockGetKeyForUser = jest.fn(async (userId: string) => {
  if (userId === 'shredded-user') return null;
  if (userId === 'active-user' || userId === 'known-user') {
    return { encryptedDek: Buffer.from('wrapped-dek'), activeDekId: 'v1', encryptionVersion: 'v1' };
  }
  return null;
});
const fakeFirestoreRegistry = { getKeyForUser: mockGetKeyForUser } as any;

// The DEK every mocked KMS unwrap resolves to -- fixed so tests can encrypt
// a real ciphertext against it and expect the route to decrypt it back.
const TEST_DEK = Buffer.alloc(32, 7);
const mockDecryptDataEncryptionKey = jest.fn(async () => TEST_DEK);
const fakeKmsClient = { decryptDataEncryptionKey: mockDecryptDataEncryptionKey } as any;

function buildApp() {
  const app = Fastify();
  return app;
}

async function registerRoutes(app: ReturnType<typeof Fastify>, overrides: Partial<{ allowedCallerServiceAccount: string }> = {}) {
  await app.register(decryptedViewsDecryptRoutes, {
    firestoreRegistry: fakeFirestoreRegistry,
    dekKmsClient: fakeKmsClient,
    allowedCallerServiceAccount: overrides.allowedCallerServiceAccount ?? ALLOWED_SA,
  });
}

describe('POST /internal/decrypted-views/batch-decrypt', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('rejects a request with no Authorization header', async () => {
    const app = buildApp();
    await registerRoutes(app);

    const response = await app.inject({
      method: 'POST',
      url: '/internal/decrypted-views/batch-decrypt',
      payload: { calls: [] },
    });

    expect(response.statusCode).toBe(403);
    expect(mockVerifyIdToken).not.toHaveBeenCalled();
  });

  it('rejects a validly-signed token that belongs to the wrong service account', async () => {
    mockVerifyIdToken.mockResolvedValue({
      getPayload: () => ({ email: 'someone-else@proj.iam.gserviceaccount.com', email_verified: true }),
    });
    const app = buildApp();
    await registerRoutes(app);

    const response = await app.inject({
      method: 'POST',
      url: '/internal/decrypted-views/batch-decrypt',
      headers: { authorization: 'Bearer some-token' },
      payload: { calls: [] },
    });

    expect(response.statusCode).toBe(403);
  });

  it('rejects a token that fails signature/audience verification', async () => {
    mockVerifyIdToken.mockRejectedValue(new Error('invalid token'));
    const app = buildApp();
    await registerRoutes(app);

    const response = await app.inject({
      method: 'POST',
      url: '/internal/decrypted-views/batch-decrypt',
      headers: { authorization: 'Bearer garbage' },
      payload: { calls: [] },
    });

    expect(response.statusCode).toBe(403);
  });

  it('fails closed (503) when the route is registered but not configured -- never silently skips auth', async () => {
    const app = buildApp();
    await registerRoutes(app, { allowedCallerServiceAccount: '' });

    const response = await app.inject({
      method: 'POST',
      url: '/internal/decrypted-views/batch-decrypt',
      headers: { authorization: 'Bearer anything' },
      payload: { calls: [] },
    });

    expect(response.statusCode).toBe(503);
    expect(mockVerifyIdToken).not.toHaveBeenCalled();
  });

  it('decrypts a batch for an authorized caller, returning null for a shredded/unknown user rather than dropping the row', async () => {
    mockVerifyIdToken.mockResolvedValue({
      getPayload: () => ({ email: ALLOWED_SA, email_verified: true }),
    });
    const app = buildApp();
    await registerRoutes(app);

    const response = await app.inject({
      method: 'POST',
      url: '/internal/decrypted-views/batch-decrypt',
      headers: { authorization: `Bearer valid-token` },
      payload: {
        requestId: 'req-1',
        calls: [
          // Well-formed 3-part shape (key_id:iv_b64:ciphertext_b64) but not
          // real ciphertext -- exercises the decrypt-attempt-fails path,
          // distinct from the parts.length<3 malformed-shape short-circuit.
          ['v1:bm90LWFuLWl2Cg==:bm90LXJlYWwtY2lwaGVydGV4dA==', 'active-user', 'tenant-a'],
          ['v1:bm90LWFuLWl2Cg==:bm90LXJlYWwtY2lwaGVydGV4dA==', 'shredded-user', 'tenant-a'],
          [null, null, null],
        ],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.replies).toHaveLength(3);
    // active-user: getKeyForUser succeeds, so the row attempts a real
    // decrypt (which will itself fail against this fixture ciphertext --
    // the point of this assertion is that a decrypt failure also yields
    // null, not a thrown error that kills the whole batch).
    expect(body.replies[0]).toBeNull();
    // shredded-user: getKeyForUser returns null (no encryptedDek) --
    // exactly how a real shredded key behaves, no cascade needed.
    expect(body.replies[1]).toBeNull();
    // malformed/empty call: null, not a crash.
    expect(body.replies[2]).toBeNull();
    expect(mockVerifyIdToken).toHaveBeenCalledWith({
      idToken: 'valid-token',
      audience: `https://${DEFAULT_HOST}`,
    });
  });

  it('successfully decrypts a real ciphertext and returns the plaintext', async () => {
    mockVerifyIdToken.mockResolvedValue({
      getPayload: () => ({ email: ALLOWED_SA, email_verified: true }),
    });
    const app = buildApp();
    await registerRoutes(app);

    const { ivB64, ciphertextB64 } = ChameleonAesGcm.encrypt('jane@example.com', 'known-user', TEST_DEK);

    const response = await app.inject({
      method: 'POST',
      url: '/internal/decrypted-views/batch-decrypt',
      headers: { authorization: 'Bearer valid-token' },
      payload: {
        requestId: 'req-2',
        calls: [[`v1:${ivB64}:${ciphertextB64}`, 'known-user', 'tenant-a']],
      },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.replies).toEqual(['jane@example.com']);
  });

  it('derives the expected audience from the request Host header, not a fixed config value', async () => {
    mockVerifyIdToken.mockResolvedValue({
      getPayload: () => ({ email: ALLOWED_SA, email_verified: true }),
    });
    const app = buildApp();
    await registerRoutes(app);

    const response = await app.inject({
      method: 'POST',
      url: '/internal/decrypted-views/batch-decrypt',
      headers: { authorization: 'Bearer valid-token', host: 'key-vault-dev-xyz.a.run.app' },
      payload: { calls: [] },
    });

    expect(response.statusCode).toBe(200);
    expect(mockVerifyIdToken).toHaveBeenCalledWith({
      idToken: 'valid-token',
      audience: 'https://key-vault-dev-xyz.a.run.app',
    });
  });

  it('rejects a malformed request body (no calls array) with a BigQuery-shaped error, not a generic 500', async () => {
    mockVerifyIdToken.mockResolvedValue({
      getPayload: () => ({ email: ALLOWED_SA, email_verified: true }),
    });
    const app = buildApp();
    await registerRoutes(app);

    const response = await app.inject({
      method: 'POST',
      url: '/internal/decrypted-views/batch-decrypt',
      headers: { authorization: 'Bearer valid-token' },
      payload: {},
    });

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).errorMessage).toBeDefined();
  });
});

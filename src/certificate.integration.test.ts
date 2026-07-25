import { jest, describe, it, expect, beforeEach, afterAll } from '@jest/globals';
import { FastifyInstance } from 'fastify';

process.env.GCP_PROJECT_ID = 'test-project';
process.env.CLOUD_KMS_REGION = 'us-central1';
process.env.CLOUD_KMS_SIGNING_KEY_RING = 'test-signing-keyring';
process.env.CLOUD_KMS_SIGNING_KEY_NAME = 'test-signing-key';
process.env.FIRESTORE_DATABASE_ID = '(default)';
process.env.FIRESTORE_COLLECTION = 'user_keys';
process.env.FIRESTORE_DELETION_REQUEST_COLLECTION = 'deletion_requests';

const mockRegistryStore: Map<string, { status: string; shredAt?: string }> = new Map();

// ESM Mocks
await jest.unstable_mockModule('../src/gcp/firestore-registry.js', () => ({
  FirestoreRegistry: class {
    getKeyStatus = jest.fn(async (userId: string) => {
      const entry = mockRegistryStore.get(userId);
      if (!entry) return null;
      return {
        status: entry.status,
        shred_at: entry.shredAt,
        created_at: '2026-01-01T00:00:00Z'
      };
    });
  }
}));

await jest.unstable_mockModule('../src/gcp/bigquery-lineage.js', () => ({
  BigQueryLineageRepository: class {
    getUserLineage = jest.fn(async (userId: string) => {
      return {
        userId,
        destinations: [
          { name: 'hubspot', lastSeen: '2026-06-01T12:00:00Z' },
          { name: 'bigquery', lastSeen: '2026-06-02T08:00:00Z' }
        ]
      };
    });
    getGhostDataFindings = jest.fn(async () => [
      {
        scope: 'RESOURCE_LEVEL',
        resourceId: 'bigquery:chameleon_dev.stg_users',
        system: 'bigquery',
        column: 'email',
        pattern: 'EMAIL',
        count: 2,
        scanner: 'ghost-data-scanner',
        lastSeen: '2026-06-02T12:00:00.000Z',
      },
    ]);
  }
}));

const mockAsymmetricSign = jest.fn(async () => 'mock-sig-header.mock-sig-payload.mock-signature');
const mockGetPublicKey = jest.fn(async () => '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEz2nHz6bvF37sprvNXq9/xdNXUYu5\nfQGLAvRlDyWA3zexY+lFarnwkl++ewAdhCmaPU1Qo04l6nJ8rslZxUV1Ag==\n-----END PUBLIC KEY-----');
await jest.unstable_mockModule('../src/gcp/cloud-kms.js', () => ({
  CloudKMSClient: class {
    asymmetricSign = mockAsymmetricSign;
    getPublicKey = mockGetPublicKey;
  }
}));

await jest.unstable_mockModule('../src/config/env.js', () => ({
  getRequiredEnv: (name: string) => process.env[name] || 'mock-value',
}));

// Import App dependencies after mocks
const { default: Fastify } = await import('fastify');
const { certificateRoutes } = await import('../src/routes/certificate.js');
const { CertificateService } = await import('../src/services/certificate-service.js');
const { FirestoreRegistry } = await import('../src/gcp/firestore-registry.js');
const { BigQueryLineageRepository } = await import('../src/gcp/bigquery-lineage.js');
const { CloudKMSClient } = await import('../src/gcp/cloud-kms.js');

describe('Certificate API Integration Tests', () => {
  let app: FastifyInstance;
  let certificateService: InstanceType<typeof CertificateService>;

  beforeAll(async (): Promise<void> => {
    const registry = new (FirestoreRegistry as any)('p', 'c', 'd');
    const lineage = new (BigQueryLineageRepository as any)();
    const kms = new (CloudKMSClient as any)('p', 'r', 'kr', 'kn');
    const gcs = { uploadAuditLog: jest.fn() };

    certificateService = new (CertificateService as any)(registry, lineage, kms, gcs as any);

    app = Fastify();
    await app.register(certificateRoutes, { certificateService });
  });

  afterAll(async (): Promise<void> => {
    if (app) await app.close();
  });

  beforeEach((): void => {
    mockRegistryStore.clear();
    mockAsymmetricSign.mockClear();
  });

  it('GET /public-key should return the PEM public key', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/public-key',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(body.algorithm).toBe('RSA_SIGN_PSS_2048_SHA256');
  });

  it('GET /certificate/:userId should return 404 if user is not shredded', async () => {
    mockRegistryStore.set('user123', { status: 'ACTIVE' });

    const response = await app.inject({
      method: 'GET',
      url: '/certificate/user123',
    });

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.body).message).toContain('not shredded');
  });

  it('GET /certificate/:userId should return signed JWT for shredded user', async () => {
    mockRegistryStore.set('user123', { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });

    const response = await app.inject({
      method: 'GET',
      url: '/certificate/user123',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.certificate).toBeDefined();
    expect(body.userId).toBe('user123');

    const claims = JSON.parse(Buffer.from(body.certificate.split('.')[1], 'base64url').toString());
    expect(claims.ghostDataSummary).toEqual([
      expect.objectContaining({
        scope: 'RESOURCE_LEVEL',
        resourceId: 'bigquery:chameleon_dev.stg_users',
        column: 'email',
        count: 2,
      }),
    ]);
    expect(claims.ghost_data_summary).toEqual(claims.ghostDataSummary);
  });
});

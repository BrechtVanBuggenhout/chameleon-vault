import { jest, describe, it, expect, beforeEach, afterAll } from '@jest/globals';
import { FastifyInstance } from 'fastify';
import * as crypto from 'crypto';

process.env.GCP_PROJECT_ID = 'test-project';
process.env.CLOUD_KMS_REGION = 'us-central1';
process.env.CLOUD_KMS_SIGNING_KEY_RING = 'test-signing-keyring';
process.env.CLOUD_KMS_SIGNING_KEY_NAME = 'test-signing-key';
process.env.FIRESTORE_DATABASE_ID = '(default)';
process.env.FIRESTORE_COLLECTION = 'user_keys';
process.env.FIRESTORE_DELETION_REQUEST_COLLECTION = 'deletion_requests';

const mockRegistryStore: Map<string, { status: string; shredAt?: string }> = new Map();
// Keyed by userId -- the deletion request a real cascade would have left
// behind. Absent entirely means "no completed cascade for this user", which
// is the exact gap that used to let /certificate issue claims for anyone
// with a shredded key regardless of whether a cascade ever ran.
// certificate_gcs_path is set once a real issueAndStoreCertificate() call
// happens (mirroring deletion-request-service.ts) -- its presence, plus
// status CERTIFICATE_ISSUED, is what lets GET /certificate/:userId return
// the stored certificate instead of re-signing.
const mockDeletionRequestStore: Map<string, {
  status: string;
  janitor_wipes: Array<{ destination: string; status: string; updated_at: string; details?: { recordsFound?: number } }>;
  certificate_gcs_path?: string;
}> = new Map();

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

await jest.unstable_mockModule('../src/gcp/deletion-request-repository.js', () => ({
  DeletionRequestRepository: class {
    getLatestCompletedDeletionRequestForUser = jest.fn(async (userId: string) => {
      const entry = mockDeletionRequestStore.get(userId);
      if (!entry) return null;
      return { deletion_request_id: `del_${userId}`, user_id: userId, ...entry };
    });
    // deletion_request_id is always `del_${userId}` in this mock scheme
    // (see above), so the id is enough to recover the userId to look up.
    getDeletionRequest = jest.fn(async (deletionRequestId: string) => {
      const userId = deletionRequestId.replace(/^del_/, '');
      const entry = mockDeletionRequestStore.get(userId);
      if (!entry) return null;
      return { deletion_request_id: deletionRequestId, user_id: userId, ...entry };
    });
  }
}));

const mockAsymmetricSign = jest.fn(async () => 'mock-sig-header.mock-sig-payload.mock-signature');
const mockGetPublicKey = jest.fn(async () => '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEz2nHz6bvF37sprvNXq9/xdNXUYu5\nfQGLAvRlDyWA3zexY+lFarnwkl++ewAdhCmaPU1Qo04l6nJ8rslZxUV1Ag==\n-----END PUBLIC KEY-----');

// Mutable, shared across tests within this file (mirrors what a real KMS
// CryptoKey's version list looks like) so the rotation tests can observe
// the version list growing. There's deliberately no separate "primary"
// pointer to track -- GCP KMS has no such concept for ASYMMETRIC_SIGN keys,
// so "current" is always just the newest entry in mockVersions itself.
const BASE_KEY_PATH = 'projects/p/locations/r/keyRings/kr/cryptoKeys/kn';
let mockVersions = [`${BASE_KEY_PATH}/cryptoKeyVersions/1`];
let mockVersionCounter = 1;

function newestVersion(): string {
  return [...mockVersions].sort((a, b) => Number(a.split('/').pop()) - Number(b.split('/').pop())).pop()!;
}

const mockGetCryptoKeyPath = jest.fn(() => BASE_KEY_PATH);
const mockGetNewestEnabledVersion = jest.fn(async () => newestVersion());
const mockListEnabledVersions = jest.fn(async () => mockVersions);
const mockCreateKeyVersion = jest.fn(async () => {
  mockVersionCounter += 1;
  const version = `${BASE_KEY_PATH}/cryptoKeyVersions/${mockVersionCounter}`;
  mockVersions = [...mockVersions, version];
  return version;
});
const mockWaitForVersionEnabled = jest.fn(async () => undefined);

await jest.unstable_mockModule('../src/gcp/cloud-kms.js', () => ({
  CloudKMSClient: class {
    asymmetricSign = mockAsymmetricSign;
    getPublicKey = mockGetPublicKey;
    getCryptoKeyPath = mockGetCryptoKeyPath;
    getNewestEnabledVersion = mockGetNewestEnabledVersion;
    listEnabledVersions = mockListEnabledVersions;
    createKeyVersion = mockCreateKeyVersion;
    waitForVersionEnabled = mockWaitForVersionEnabled;
  }
}));

await jest.unstable_mockModule('../src/config/env.js', () => ({
  getRequiredEnv: (name: string) => process.env[name] || 'mock-value',
}));

// Fake GCS: an in-memory map keyed by the gs:// path uploadCertificate
// returns, so downloadCertificate can read back exactly what was stored --
// this is what lets the "return stored cert, don't re-sign" tests actually
// prove the round trip.
const mockGcsStore = new Map<string, {
  certificate: string;
  userId: string;
  deletionRequestId: string;
  timestamp: string;
  hash: string;
  previousCertificateHash: string | null;
  chainSequence?: number;
}>();
const mockUploadCertificate = jest.fn(async (
  userId: string,
  deletionRequestId: string,
  certificate: string,
  hash: string,
  tenantId: string = 'default-tenant',
  chain?: { previousCertificateHash: string | null; chainSequence: number }
) => {
  const gcsPath = `gs://test-bucket/certificates/${tenantId}/certificate-${deletionRequestId}.json`;
  mockGcsStore.set(gcsPath, {
    certificate,
    userId,
    deletionRequestId,
    timestamp: new Date().toISOString(),
    hash,
    previousCertificateHash: chain?.previousCertificateHash ?? null,
    chainSequence: chain?.chainSequence,
  });
  return gcsPath;
});
const mockDownloadCertificate = jest.fn(async (gcsPath: string) => {
  const entry = mockGcsStore.get(gcsPath);
  if (!entry) throw new Error(`No such object: ${gcsPath}`);
  return entry;
});

await jest.unstable_mockModule('../src/gcp/gcs-client.js', () => ({
  GCSClient: class {
    uploadCertificate = mockUploadCertificate;
    downloadCertificate = mockDownloadCertificate;
  }
}));

// Fake certificate chain: a per-tenant {sequence, lastHash} map, mirroring
// exactly what the real Firestore-transaction-backed repository tracks.
// Deliberately does NOT test Firestore transaction mechanics itself (no
// test in this repo mocks @google-cloud/firestore directly -- see
// AnalystAccessRepository's equivalent transaction, tested the same way,
// at the service level with the repository mocked away).
const mockChainStore = new Map<string, { sequence: number; lastHash: string | null }>();
// Mirrors the real certificate_chain_entries index -- keyed by the
// certificate's own hash, written alongside the chain head. Backs the fake
// getEntryByHash below, the same way mockGcsStore backs downloadCertificate.
const mockChainEntriesStore = new Map<string, { tenant_id: string; sequence: number; previous_hash: string | null; deletion_request_id: string }>();
const mockAppendToChain = jest.fn(async (
  tenantId: string,
  deletionRequestId: string,
  sign: (previousHash: string | null, sequence: number) => Promise<{ certificate: string; certificateHash: string }>
) => {
  const current = mockChainStore.get(tenantId) ?? { sequence: 0, lastHash: null };
  const previousHash = current.lastHash;
  const sequence = current.sequence + 1;
  const result = await sign(previousHash, sequence);
  mockChainStore.set(tenantId, { sequence, lastHash: result.certificateHash });
  mockChainEntriesStore.set(result.certificateHash, {
    tenant_id: tenantId,
    sequence,
    previous_hash: previousHash,
    deletion_request_id: deletionRequestId,
  });
  return { ...result, previousHash, sequence };
});
const mockGetEntryByHash = jest.fn(async (hash: string) => mockChainEntriesStore.get(hash) ?? null);

await jest.unstable_mockModule('../src/gcp/certificate-chain-repository.js', () => ({
  CertificateChainRepository: class {
    appendToChain = mockAppendToChain;
    getEntryByHash = mockGetEntryByHash;
  }
}));

// Import App dependencies after mocks
const { default: Fastify } = await import('fastify');
const { certificateRoutes } = await import('../src/routes/certificate.js');
const { CertificateService } = await import('../src/services/certificate-service.js');
const { FirestoreRegistry } = await import('../src/gcp/firestore-registry.js');
const { BigQueryLineageRepository } = await import('../src/gcp/bigquery-lineage.js');
const { CloudKMSClient } = await import('../src/gcp/cloud-kms.js');
const { DeletionRequestRepository } = await import('../src/gcp/deletion-request-repository.js');
const { CertificateChainRepository } = await import('../src/gcp/certificate-chain-repository.js');
const { GCSClient } = await import('../src/gcp/gcs-client.js');

describe('Certificate API Integration Tests', () => {
  let app: FastifyInstance;
  let certificateService: InstanceType<typeof CertificateService>;

  beforeAll(async (): Promise<void> => {
    const registry = new (FirestoreRegistry as any)('p', 'c', 'd');
    const lineage = new (BigQueryLineageRepository as any)();
    const kms = new (CloudKMSClient as any)('p', 'r', 'kr', 'kn');
    const gcs = new (GCSClient as any)('p', 'test-bucket');
    const deletionRequestRepo = new (DeletionRequestRepository as any)('p', 'c', 'd');
    const chainRepo = new (CertificateChainRepository as any)('p', 'c', 'd');

    certificateService = new (CertificateService as any)(registry, lineage, kms, gcs, deletionRequestRepo, chainRepo);

    app = Fastify();
    await app.register(certificateRoutes, { certificateService });
  });

  afterAll(async (): Promise<void> => {
    if (app) await app.close();
  });

  beforeEach((): void => {
    mockRegistryStore.clear();
    mockDeletionRequestStore.clear();
    mockGcsStore.clear();
    mockChainStore.clear();
    mockChainEntriesStore.clear();
    mockAsymmetricSign.mockClear();
    mockGetNewestEnabledVersion.mockClear();
    mockListEnabledVersions.mockClear();
    mockCreateKeyVersion.mockClear();
    mockWaitForVersionEnabled.mockClear();
    mockUploadCertificate.mockClear();
    mockDownloadCertificate.mockClear();
    mockAppendToChain.mockClear();
    mockGetEntryByHash.mockClear();
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

  it('GET /certificate/:userId should return 404 when the key is shredded but no cascade ever completed', async () => {
    // This is the exact gap that let /certificate issue a certificate for
    // anyone with a shredded key, regardless of whether any SaaS cleanup
    // was ever verified -- no entry in mockDeletionRequestStore at all.
    mockRegistryStore.set('user123', { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });

    const response = await app.inject({
      method: 'GET',
      url: '/certificate/user123',
    });

    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.body).message).toContain('no completed deletion cascade');
  });

  it('GET /certificate/:userId should return signed JWT for a user with a real completed cascade', async () => {
    mockRegistryStore.set('user123', { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });
    mockDeletionRequestStore.set('user123', {
      status: 'CASCADE_COMPLETE',
      janitor_wipes: [
        { destination: 'hubspot', status: 'SUCCEEDED', updated_at: '2026-06-02T10:05:00Z', details: { recordsFound: 3 } },
        { destination: 'salesforce', status: 'SUCCEEDED', updated_at: '2026-06-02T10:06:00Z', details: { recordsFound: 0 } },
      ],
    });

    const response = await app.inject({
      method: 'GET',
      url: '/certificate/user123',
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.certificate).toBeDefined();
    expect(body.userId).toBe('user123');

    const claims = JSON.parse(Buffer.from(body.certificate.split('.')[1], 'base64url').toString());

    // The real point of this fix: a destination with real records found and
    // deleted reads ERASED; a destination that was genuinely checked and had
    // nothing there reads CONFIRMED_ABSENT, not a blanket ERASED for both.
    expect(claims.lineageSummary).toEqual([
      { system: 'hubspot', status: 'ERASED', timestamp: '2026-06-02T10:05:00Z' },
      { system: 'salesforce', status: 'CONFIRMED_ABSENT', timestamp: '2026-06-02T10:06:00Z' },
    ]);

    expect(claims.ghostDataSummary).toEqual([
      expect.objectContaining({
        scope: 'RESOURCE_LEVEL',
        resourceId: 'bigquery:chameleon_dev.stg_users',
        column: 'email',
        count: 2,
      }),
    ]);
    expect(claims.ghost_data_summary).toEqual(claims.ghostDataSummary);

    // Coverage is stated honestly: both destinations were actually checked
    // (and both succeeded, per the CASCADE_COMPLETE invariant), scoped to
    // the connector types this system can wipe -- not implied as exhaustive.
    expect(claims.lineageCoverage).toEqual({
      destinationsChecked: 2,
      destinationsSucceeded: 2,
      knownDestinationTypes: expect.arrayContaining(['hubspot', 'salesforce']),
    });
    // No scanner in this system records what was scanned, only matches it
    // happened to find -- the findings above must not be read as "confirmed
    // scanned, zero elsewhere found" without this flag alongside them.
    expect(claims.ghostDataScanCoverage).toBe('NOT_TRACKED');
    // States the actual mechanism (Firestore DEK erasure), not a Cloud KMS
    // key-destroy call -- see certificate-service.ts / ARCHITECTURE.md.
    expect(claims.keyDestructionMethod).toBe('DEK_ERASURE');
  });

  it('GET /certificate/:userId should never surface a FAILED wipe, even defensively', async () => {
    // CASCADE_COMPLETE should never coexist with a FAILED wipe in practice
    // (deletion-request-service.ts routes any real failure to
    // CASCADE_PARTIAL_FAILURE instead) -- this only guards against that
    // invariant ever being violated, e.g. by a future bug elsewhere.
    mockRegistryStore.set('user123', { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });
    mockDeletionRequestStore.set('user123', {
      status: 'CASCADE_COMPLETE',
      janitor_wipes: [
        { destination: 'hubspot', status: 'SUCCEEDED', updated_at: '2026-06-02T10:05:00Z', details: { recordsFound: 1 } },
        { destination: 'salesforce', status: 'FAILED', updated_at: '2026-06-02T10:06:00Z' },
      ],
    });

    const response = await app.inject({
      method: 'GET',
      url: '/certificate/user123',
    });

    expect(response.statusCode).toBe(200);
    const claims = JSON.parse(Buffer.from(JSON.parse(response.body).certificate.split('.')[1], 'base64url').toString());
    expect(claims.lineageSummary).toEqual([
      { system: 'hubspot', status: 'ERASED', timestamp: '2026-06-02T10:05:00Z' },
    ]);
  });

  it('GET /certificate/:userId should return an empty lineageSummary when no SaaS cleanup was ever needed', async () => {
    mockRegistryStore.set('user123', { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });
    mockDeletionRequestStore.set('user123', { status: 'CASCADE_COMPLETE', janitor_wipes: [] });

    const response = await app.inject({
      method: 'GET',
      url: '/certificate/user123',
    });

    expect(response.statusCode).toBe(200);
    const claims = JSON.parse(Buffer.from(JSON.parse(response.body).certificate.split('.')[1], 'base64url').toString());
    expect(claims.lineageSummary).toEqual([]);
  });

  it('GET /.well-known/jwks.json should return exactly one key before any rotation', async () => {
    const response = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0]).toMatchObject({ kid: newestVersion(), use: 'sig', alg: 'PS256' });
  });

  it('POST /admin/signing-key/rotate should mint a new version, with no promote-to-primary step', async () => {
    const versionBefore = newestVersion();

    const response = await app.inject({ method: 'POST', url: '/admin/signing-key/rotate' });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.status).toBe('rotated');
    expect(body.previousVersion).toBe(versionBefore);
    expect(body.newVersion).not.toBe(versionBefore);
    expect(mockCreateKeyVersion).toHaveBeenCalledTimes(1);
    expect(mockWaitForVersionEnabled).toHaveBeenCalledWith(body.newVersion);
    // The new version is "current" simply by being the newest ENABLED one --
    // GCP KMS has no primary-version concept for ASYMMETRIC_SIGN keys, so
    // there's no separate promotion call to assert here.
    expect(newestVersion()).toBe(body.newVersion);
  });

  it('GET /.well-known/jwks.json should include both the old and new key after rotation', async () => {
    // The previous test already rotated once, so two ENABLED versions exist.
    const response = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.keys.map((k: { kid: string }) => k.kid).sort()).toEqual([...mockVersions].sort());
    expect(mockVersions.length).toBeGreaterThan(1);
  });

  it('GET /certificate/:userId should sign with the newest version after rotation', async () => {
    mockRegistryStore.set('user456', { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });
    mockDeletionRequestStore.set('user456', { status: 'CASCADE_COMPLETE', janitor_wipes: [] });

    const response = await app.inject({ method: 'GET', url: '/certificate/user456' });

    expect(response.statusCode).toBe(200);
    const certificate = JSON.parse(response.body).certificate as string;
    const header = JSON.parse(Buffer.from(certificate.split('.')[0], 'base64url').toString());
    expect(header.kid).toBe(newestVersion());
  });

  describe('Certificate hash chain', () => {
  function setupShreddedUser(userId: string): void {
    mockRegistryStore.set(userId, { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });
    mockDeletionRequestStore.set(userId, { status: 'CASCADE_COMPLETE', janitor_wipes: [] });
  }

  function decodeClaims(certificate: string): Record<string, unknown> {
    return JSON.parse(Buffer.from(certificate.split('.')[1], 'base64url').toString());
  }

  it('signs the first certificate for a tenant with no previous hash and sequence 1', async () => {
    setupShreddedUser('chain-user-1');

    const { certificate } = await certificateService.issueAndStoreCertificate('chain-user-1', 'del_chain-user-1', 'tenant-a');
    const claims = decodeClaims(certificate);

    expect(claims.previousCertificateHash).toBeNull();
    expect(claims.chainSequence).toBe(1);
  });

  it('links the second certificate in a tenant to the sha256 of the first', async () => {
    setupShreddedUser('chain-user-2a');
    setupShreddedUser('chain-user-2b');

    const first = await certificateService.issueAndStoreCertificate('chain-user-2a', 'del_chain-user-2a', 'tenant-b');
    const second = await certificateService.issueAndStoreCertificate('chain-user-2b', 'del_chain-user-2b', 'tenant-b');

    const expectedFirstHash = crypto.createHash('sha256').update(first.certificate).digest('hex');
    const secondClaims = decodeClaims(second.certificate);

    expect(secondClaims.previousCertificateHash).toBe(expectedFirstHash);
    expect(secondClaims.chainSequence).toBe(2);
  });

  it('keeps independent chains per tenant, both starting at sequence 1', async () => {
    setupShreddedUser('chain-user-3a');
    setupShreddedUser('chain-user-3b');

    const a = await certificateService.issueAndStoreCertificate('chain-user-3a', 'del_chain-user-3a', 'tenant-x');
    const b = await certificateService.issueAndStoreCertificate('chain-user-3b', 'del_chain-user-3b', 'tenant-y');

    expect(decodeClaims(a.certificate).chainSequence).toBe(1);
    expect(decodeClaims(b.certificate).chainSequence).toBe(1);
    expect(decodeClaims(a.certificate).previousCertificateHash).toBeNull();
    expect(decodeClaims(b.certificate).previousCertificateHash).toBeNull();
  });

  it('stores the chain fields in the GCS wrapper alongside the certificate', async () => {
    setupShreddedUser('chain-user-4');

    const { gcsPath } = await certificateService.issueAndStoreCertificate('chain-user-4', 'del_chain-user-4', 'tenant-c');
    const stored = mockGcsStore.get(gcsPath)!;

    expect(stored.chainSequence).toBe(1);
    expect(stored.previousCertificateHash).toBeNull();
  });
});

describe('GET /certificate-chain/by-hash/:hash', () => {
  function setupShreddedUser(userId: string): void {
    mockRegistryStore.set(userId, { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });
    mockDeletionRequestStore.set(userId, { status: 'CASCADE_COMPLETE', janitor_wipes: [] });
  }

  it('returns the certificate whose hash matches, letting a verifier walk one chain link backward', async () => {
    setupShreddedUser('by-hash-1a');
    setupShreddedUser('by-hash-1b');

    const first = await certificateService.issueAndStoreCertificate('by-hash-1a', 'del_by-hash-1a', 'tenant-by-hash');
    // Mirrors what deletion-request-service.ts does once issuance succeeds --
    // the by-hash lookup resolves through the deletion request's stored
    // certificate_gcs_path, same as GET /certificate/:userId does.
    mockDeletionRequestStore.set('by-hash-1a', { status: 'CERTIFICATE_ISSUED', janitor_wipes: [], certificate_gcs_path: first.gcsPath });

    const second = await certificateService.issueAndStoreCertificate('by-hash-1b', 'del_by-hash-1b', 'tenant-by-hash');
    const secondClaims = JSON.parse(Buffer.from(second.certificate.split('.')[1], 'base64url').toString());

    // The link a verifier would actually follow: the second certificate's
    // previousCertificateHash should resolve back to the exact first one.
    const response = await app.inject({
      method: 'GET',
      url: `/certificate-chain/by-hash/${secondClaims.previousCertificateHash}`,
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body).certificate).toBe(first.certificate);
  });

  it('returns 404 for a hash no certificate was ever issued with', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/certificate-chain/by-hash/not-a-real-hash',
    });

    expect(response.statusCode).toBe(404);
  });
});

describe('GET /certificate/:userId returns the exact stored certificate', () => {
  it('returns the stored certificate byte-for-byte instead of re-signing on repeated calls', async () => {
    mockRegistryStore.set('stored-user', { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });
    mockDeletionRequestStore.set('stored-user', { status: 'CASCADE_COMPLETE', janitor_wipes: [] });

    const { certificate: issued, gcsPath } = await certificateService.issueAndStoreCertificate('stored-user', 'del_stored-user', 'default-tenant');
    // Mirrors what deletion-request-service.ts does once issuance succeeds.
    mockDeletionRequestStore.set('stored-user', { status: 'CERTIFICATE_ISSUED', janitor_wipes: [], certificate_gcs_path: gcsPath });
    mockAsymmetricSign.mockClear(); // only count signing that happens from here on

    const firstResponse = await app.inject({ method: 'GET', url: '/certificate/stored-user' });
    const secondResponse = await app.inject({ method: 'GET', url: '/certificate/stored-user' });

    expect(firstResponse.statusCode).toBe(200);
    expect(secondResponse.statusCode).toBe(200);
    const firstCert = JSON.parse(firstResponse.body).certificate;
    const secondCert = JSON.parse(secondResponse.body).certificate;

    // The actual bug this fixes: repeated GETs used to each mint a fresh
    // JWT (different jti/iat/signature) for the same underlying deletion.
    expect(firstCert).toBe(issued);
    expect(secondCert).toBe(issued);
    expect(mockAsymmetricSign).not.toHaveBeenCalled();
    expect(mockDownloadCertificate).toHaveBeenCalledTimes(2);
  });

  it('falls back to signing on demand (unchained) when no certificate was ever stored', async () => {
    // status CASCADE_COMPLETE with no certificate_gcs_path -- the rare case
    // of a prior CERTIFICATE_ISSUED transition failing mid-flight.
    mockRegistryStore.set('fallback-user', { status: 'SHREDDED', shredAt: '2026-06-02T10:00:00Z' });
    mockDeletionRequestStore.set('fallback-user', { status: 'CASCADE_COMPLETE', janitor_wipes: [] });

    const response = await app.inject({ method: 'GET', url: '/certificate/fallback-user' });

    expect(response.statusCode).toBe(200);
    const certificate = JSON.parse(response.body).certificate as string;
    const claims = JSON.parse(Buffer.from(certificate.split('.')[1], 'base64url').toString());

    // Unchained: null, not a real sequence number -- a GET must never
    // consume a slot in the tenant's certificate chain.
    expect(claims.previousCertificateHash).toBeNull();
    expect(claims.chainSequence).toBeNull();
    expect(mockAppendToChain).not.toHaveBeenCalled();
  });
  });
});

import { jest, describe, it, expect, beforeEach, afterAll } from '@jest/globals';
import { DeletionRequest } from '../src/types/deletion-request.js';

// Define mock stores at the top level with 'mock' prefix so they are accessible in factories
const mockRegistryStore: Map<string, any> = new Map();
const mockLineageStore: Map<string, any[]> = new Map();
const mockDeletionRequestStore: Map<string, DeletionRequest> = new Map();
const mockHotPathDestinationStore: Map<string, any[]> = new Map();

// Use unstable_mockModule for Pure ESM compatibility in Node.js + Jest.
// In ESM mode (--experimental-vm-modules), static imports are resolved before code execution.
// jest.mock() hoisting often fails to intercept these imports. 
// unstable_mockModule must be awaited BEFORE the target modules are imported.
await jest.unstable_mockModule('../src/config/env.js', () => ({
  getRequiredEnv: jest.fn((key: string) => {
    switch (key) {
      case 'GCP_PROJECT_ID': return 'test-project';
      case 'CLOUD_KMS_REGION': return 'us-central1';
      case 'CLOUD_KMS_KEY_RING': return 'test-keyring';
      case 'CLOUD_KMS_KEY_NAME': return 'test-key';
      case 'FIRESTORE_COLLECTION': return 'user_keys';
      case 'FIRESTORE_DELETION_REQUEST_COLLECTION': return 'deletion_requests';
      default: return 'mock-value';
    }
  }),
}));

await jest.unstable_mockModule('../src/gcp/bigquery-lineage.js', () => ({
  BigQueryLineageRepository: class {
    getUserLineage = jest.fn(async (userId: string, tenantId: string = 'default-tenant') => {
      const events = mockLineageStore.get(userId) || [];
      const destinations = events.filter((e: any) => (e.tenantId || 'default-tenant') === tenantId).reduce((acc: any[], e: any) => {
        const existing = acc.find(d => d.name === e.destination);
        if (existing) {
          if (new Date(e.timestamp) > new Date(existing.lastSeen)) {
            existing.lastSeen = e.timestamp;
          }
        } else {
          acc.push({ name: e.destination, lastSeen: e.timestamp });
        }
        return acc;
      }, []);
      return {
        userId,
        destinations: destinations
      };
    });
    getGhostDataFindings = jest.fn(async (userId: string, tenantId: string = 'default-tenant') => {
      const events = [
        ...(mockLineageStore.get(userId) || []),
        ...(mockLineageStore.get('UNKNOWN') || []),
      ];

      return events
        .filter((event: any) => (event.tenantId || 'default-tenant') === tenantId)
        .filter((event: any) => (event.dataClassification || event.data_classification) === 'GHOST_DATA')
        .map((event: any) => {
          const metadata = event.context || event.metadata || {};
          return {
            scope: (event.userId || event.user_id) === 'UNKNOWN' ? 'RESOURCE_LEVEL' : 'USER_LINKED',
            resourceId: metadata.resource_id || event.destination,
            system: metadata.system || event.destination,
            column: metadata.column,
            pattern: metadata.pattern,
            count: metadata.count,
            confidence: metadata.confidence,
            scanner: metadata.scanner || event.source,
            lastSeen: event.timestamp instanceof Date ? event.timestamp.toISOString() : String(event.timestamp),
          };
        });
    });
    recordEvent = jest.fn(async (event: any) => {
      const uId = event.userId || event.user_id;
      const events = mockLineageStore.get(uId) || [];
      const newEvent = { ...event, eventType: event.eventType || 'UNKNOWN', timestamp: new Date() };
      events.push(newEvent);
      mockLineageStore.set(uId, events);
      return 'mock-event-id-123';
    });
  }
}));

// Mock CloudKMSClient
const mockGenerateAndEncryptDek = jest.fn(async () => Buffer.alloc(32, 'a'));
const mockEncryptDek = jest.fn(async (dek: Buffer) => dek);
const mockDecryptDek = jest.fn(async (dek: Buffer) => dek);
await jest.unstable_mockModule('../src/gcp/cloud-kms.js', () => ({
  CloudKMSClient: class {
    ensureTenantKey = jest.fn(async () => 'mock-tenant-key');
    generateAndEncryptDek = mockGenerateAndEncryptDek;
    encryptDataEncryptionKey = mockEncryptDek;
    decryptDataEncryptionKey = mockDecryptDek;
  }
}));

await jest.unstable_mockModule('../src/gcp/firestore-registry.js', () => ({
  FirestoreRegistry: class {
    getKeyForUser = jest.fn(async (userId: string, _tenantId: string = 'default-tenant', keyVersionId?: string) => {
      const entry = mockRegistryStore.get(userId);
      if (!entry || entry.status === 'SHREDDED') return null; // Consistent with API_SPECIFICATION.md
      // If DEK material is explicitly removed, treat as unrecoverable
      if (!entry.deks || Object.keys(entry.deks).length === 0) {
        return null;
      }
      const targetDekId = keyVersionId || entry.activeDekId;
      const dekBase64 = entry.deks[targetDekId];
      if (!dekBase64) return null;

      return {
        encryptedDek: Buffer.from(dekBase64, 'base64'),
        activeDekId: entry.activeDekId, // Ensure this is always a string for active keys
        encryptionVersion: entry.encryptionVersion || 'v1', // Ensure default if not set
      };
    });
    setKeyForUser = jest.fn(async (userId: string, dek: Buffer, _tenantId: string = 'default-tenant') => {
      mockRegistryStore.set(userId, { // This `dek` is already encrypted by KMS
        deks: { v1: dek.toString('base64') },
        activeDekId: 'v1',
        status: 'ACTIVE',
        encryptionVersion: 'v1', // Match test expectations
        tokenization: { algorithm: 'HMAC-SHA256', tokenKeyId: 'chameleon-token-key-v1' },
        createdAt: new Date(),
      });
    });
    rotateKeyForUser = jest.fn(async (userId: string, newDek: Buffer, _tenantId: string = 'default-tenant') => {
      const entry = mockRegistryStore.get(userId);
      if (!entry) throw new Error('User key not found for rotation');
      if (entry.status === 'SHREDDED') throw new Error('Cannot rotate a shredded key');

      const newVersionId = `v${Object.keys(entry.deks).length + 1}`;
      entry.deks[newVersionId] = newDek.toString('base64');
      entry.activeDekId = newVersionId;
      entry.rotatedAt = new Date(); // Timestamp.now() in real code
      entry.status = 'ACTIVE'; // Status remains active, rotatedAt tracks the event
      return newVersionId;
    });
    shredKeyForUser = jest.fn(async (userId: string, _tenantId: string = 'default-tenant') => {
      const entry = mockRegistryStore.get(userId);
      if (entry) {
        entry.status = 'SHREDDED'; // Consistent with API_SPECIFICATION.md
        entry.shredAt = new Date();
        entry.deks = {}; // Remove DEK material
      }
    });
    getKeyStatus = jest.fn(async (userId: string, _tenantId: string = 'default-tenant') => {
      const entry = mockRegistryStore.get(userId);
      if (!entry) return null;
      const hotPathDestinations = (mockHotPathDestinationStore.get(userId) || [])
        .filter((item) => item.tenantId === _tenantId)
        .map((item) => item.destination);
      return {
        status: entry.status,
        created_at: entry.createdAt || new Date(),
        shred_at: entry.shredAt,
        rotated_at: entry.rotatedAt,
        encryption_version: entry.encryptionVersion || 'v1',
        tokenization: entry.tokenization || undefined,
        active_dek_id: entry.activeDekId,
        destinations: hotPathDestinations.length > 0 ? hotPathDestinations : entry.destinations,
      };
    });
    addDestinationToUser = jest.fn(async (userId: string, destination: string, tenantId: string = 'default-tenant') => {
      const destinations = mockHotPathDestinationStore.get(userId) || [];
      destinations.push({ destination, tenantId });
      mockHotPathDestinationStore.set(userId, destinations);
    });
  }
}));

await jest.unstable_mockModule('../src/services/janitor.js', () => ({
  JanitorService: class {
    processCleanup = jest.fn(async (_userId: string) => {
      return []; // Return empty array to prevent iteration 500s
    });
    createCleanupPlan = jest.fn(async (userId: string) => {
      const events = mockLineageStore.get(userId) || [];
      return events
        .filter((event) => ['hubspot', 'salesforce', 'segment', 'mailchimp'].includes(event.destination))
        .map((event) => ({
          userId,
          destination: event.destination,
          status: 'PENDING',
          attempts: 0,
        }));
    });
  }
}));

await jest.unstable_mockModule('../src/gcp/deletion-request-repository.js', () => ({
  DeletionRequestRepository: class {
    createDeletionRequest = jest.fn(async (userId: string, operationId: string, tenantId: string = 'default-tenant') => {
      const request = {
        id: operationId,
        deletionRequestId: operationId,
        deletion_request_id: operationId,
        tenant_id: tenantId,
        userId,
        user_id: userId,
        status: 'SHRED_REQUESTED',
        createdAt: new Date(),
        requestedAt: new Date(),
        statusHistory: [{ status: 'SHRED_REQUESTED', timestamp: new Date() }],
        janitorWipes: [],
      };
      mockDeletionRequestStore.set(operationId, request);
      return request;
    });
    getDeletionRequest = jest.fn(async (id: string) => mockDeletionRequestStore.get(id) || null);
    getActiveDeletionRequestForUser = jest.fn(async (userId: string, tenantId: string = 'default-tenant') => {
      return Array.from(mockDeletionRequestStore.values()).find(r => (r.userId === userId || r.user_id === userId) && (r.tenant_id || 'default-tenant') === tenantId && r.status !== 'CERTIFICATE_ISSUED') || null;
    });
    updateDeletionRequestStatus = jest.fn(async (id: string, status: any, fields: any) => {
      const request = mockDeletionRequestStore.get(id);
      if (request) {
        Object.assign(request, fields, { status });
        request.statusHistory.push({ status, timestamp: new Date() });
      }
    });
    updateJanitorWipeStatus = jest.fn(async () => {});
  }
}));

// Dynamically import dependencies AFTER mocks are established.
// This ensures the route handlers receive the mocked classes.
const { default: Fastify } = await import('fastify');
const { default: cors } = await import('@fastify/cors');
const { default: helmet } = await import('@fastify/helmet');
const { healthRoutes } = await import('../src/routes/health.js');
const { cryptoRoutes } = await import('../src/routes/crypto.js');
const { lineageRoutes } = await import('../src/routes/lineage.js');
const { deletionRequestRoutes } = await import('../src/routes/deletion-requests.js');
const { registerRequestLogging } = await import('../src/middleware/request-logging.js');
const { DeterministicAES } = await import('../src/crypto/deterministic-aes.js');
const { CloudKMSClient } = await import('../src/gcp/cloud-kms.js');
const { FirestoreRegistry } = await import('../src/gcp/firestore-registry.js');
const { BigQueryLineageRepository } = await import('../src/gcp/bigquery-lineage.js');
const { DeletionRequestService } = await import('../src/services/deletion-request-service.js');
const { JanitorService } = await import('../src/services/janitor.js');
const { DeletionRequestRepository } = await import('../src/gcp/deletion-request-repository.js');

import type { FastifyInstance } from 'fastify';

describe('Crypto API Integration Tests', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    process.env.GCP_PROJECT_ID = 'test-project';
    const kmsClient = new (CloudKMSClient as any)();
    const firestoreRegistry = new (FirestoreRegistry as any)();
    const lineageRepository = new (BigQueryLineageRepository as any)();
    const janitorService = new (JanitorService as any)();
    const mockCertificateService = { issueAndStoreCertificate: jest.fn().mockResolvedValue({ gcsPath: 'mock-gcs-path' }) };
    const deletionRequestRepo = new (DeletionRequestRepository as any)();
    const deletionRequestService = new (DeletionRequestService as any)(
      deletionRequestRepo, firestoreRegistry, lineageRepository, janitorService, kmsClient, mockCertificateService
    );

    app = Fastify({ logger: false });
    await app.register(cors);
    await app.register(helmet);
    await registerRequestLogging(app);
    await app.register(healthRoutes);
    await app.register(cryptoRoutes, { kmsClient, firestoreRegistry, lineageRepository, deletionRequestService });
    await app.register(lineageRoutes, { lineageRepository, firestoreRegistry, janitorService });
    await app.register(deletionRequestRoutes, { deletionRequestService });
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockRegistryStore.clear();
    mockLineageStore.clear();
    mockDeletionRequestStore.clear();
    mockHotPathDestinationStore.clear();
    mockGenerateAndEncryptDek.mockClear();
    mockGenerateAndEncryptDek.mockResolvedValue(Buffer.alloc(32, 'a')); // Reset mock for each test
  });

  describe('Health Endpoints', () => {
    it('GET /health should return 200 with status ok', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/health',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('ok');
      expect(body.service).toBe('chameleon-key-vault');
    });

    it('GET /ready should return 200 with ready true', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/ready',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.ready).toBe(true);
    });
  });

  describe('POST /key/generate', () => {
    it('should generate a new key for user', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user123' },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('GENERATED');
      expect(body.userId).toBe('user123');
    });

    it('should return 200 if key already exists', async () => {
      // Generate first time
      await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user123' },
      });

      // Try again
      const response = await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user123' },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('EXISTS');
    });

    it('should reject invalid userId (empty)', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: '' },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error).toBeDefined();
    });

    it('should reject invalid userId (too long)', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'a'.repeat(100) },
      });

      expect(response.statusCode).toBe(400);
    });

    it('should reject invalid userId (special characters)', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user@123!' },
      });

      expect(response.statusCode).toBe(400);
    });
  });

  describe('POST /encrypt', () => {
    beforeEach(async () => {
      // Generate key before each encrypt test
      await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user123' },
      });
    });

    it('should encrypt plaintext and return base64 ciphertext', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/encrypt',
        payload: {
          plaintext: 'john.doe@example.com',
          userId: 'user123',
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.ciphertext).toBeDefined();
      expect(body.userId).toBe('user123');
      expect(body.timestamp).toBeDefined();
      // Check it's valid base64
      expect(() => Buffer.from(body.ciphertext, 'base64')).not.toThrow();
    });

    it('should return 404 if user key not found', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/encrypt',
        payload: {
          plaintext: 'test',
          userId: 'nonexistentuser',
        },
      });

      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('not found');
    });

    it('should reject empty plaintext', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/encrypt',
        payload: {
          plaintext: '',
          userId: 'user123',
        },
      });

      expect(response.statusCode).toBe(400);
    });

    it('should reject plaintext > 10KB', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/encrypt',
        payload: {
          plaintext: 'x'.repeat(11000),
          userId: 'user123',
        },
      });

      expect(response.statusCode).toBe(400);
    });
  });

  describe('POST /decrypt', () => {
    let ciphertext: string;

    beforeEach(async () => {
      mockLineageStore.clear(); // Clear lineage for each decrypt test to avoid interference
      // Generate key and encrypt test data
      await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user123' },
      });

      const encryptResponse = await app.inject({
        method: 'POST',
        url: '/encrypt',
        payload: {
          plaintext: 'john.doe@example.com',
          userId: 'user123',
        },
      });

      // The ciphertext now includes the version prefix
      const body = JSON.parse(encryptResponse.body);
      ciphertext = body.ciphertext;
    });

    it('should decrypt ciphertext back to plaintext', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/decrypt',
        payload: {
          ciphertext,
          userId: 'user123',
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.plaintext).toBe('john.doe@example.com');
      expect(body.userId).toBe('user123');
    });

    it('should return 404 if user key not found', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/decrypt',
        payload: {
          ciphertext,
          userId: 'nonexistentuser',
        },
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.body).error).toContain('User key not found');
    });

    it('should return 404 if user key was shredded', async () => {
      // Shred the key
      await app.inject({
        method: 'DELETE',
        url: '/key/shred',
        payload: { userId: 'user123' },
      });

      // Try to decrypt
      const response = await app.inject({
        method: 'POST',
        url: '/decrypt',
        payload: {
          ciphertext,
          userId: 'user123',
        },
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.body).error).toMatch(/User key not found/);
    });

    it('should fail decryption with different userId', async () => {
      await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user999' },
      });

      const response = await app.inject({
        method: 'POST',
        url: '/decrypt',
        payload: {
          ciphertext,
          userId: 'user999',
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error).toMatch(/Failed to decrypt/);
    });

    it('should fail decryption with tampered ciphertext', async () => {
      const [version, actualCiphertext] = ciphertext.split(':', 2);
      const tamperedBody = Buffer.from(actualCiphertext, 'base64');
      tamperedBody[0] ^= 0xff; // Flip bits in the actual encrypted data
      const tamperedCiphertext = `${version}:${tamperedBody.toString('base64')}`;

      const response = await app.inject({
        method: 'POST',
        url: '/decrypt',
        payload: {
          ciphertext: tamperedCiphertext,
          userId: 'user123',
        },
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.body).error).toContain('Failed to decrypt. Ciphertext may be invalid or tampered.');
    });

    it('should reject invalid base64 ciphertext', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/decrypt',
        payload: {
          ciphertext: 'not-valid-base64!!!',
          userId: 'user123',
        },
      });

      expect(response.statusCode).toBe(400);
    });
  });

  describe('GET /key-status/:userId', () => {
    beforeEach(async () => {
      await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user123' },
      });
    });

    it('should return key status for active key', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/key-status/user123',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('ACTIVE');
      expect(body.userId).toBe('user123');
      expect(body.createdAt).toBeDefined();
    });

    it('should return 404 if key not found', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/key-status/nonexistentuser',
      });

      expect(response.statusCode).toBe(404);
    });

    it('should return SHREDDED status after key shredding', async () => {
      // Shred the key
      await app.inject({
        method: 'DELETE',
        url: '/key/shred',
        payload: { userId: 'user123' },
      });

      // Get status
      const response = await app.inject({
        method: 'GET',
        url: '/key-status/user123',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('SHREDDED');
      expect(body.shredAt).toBeDefined();
    });
  });

  describe('DELETE /key/shred', () => {
    beforeEach(async () => {
      await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user123' },
      });
    });

    it('should shred key successfully', async () => {
      const response = await app.inject({
        method: 'DELETE',
        url: '/key/shred',
        payload: { userId: 'user123' },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('CERTIFICATE_ISSUED'); // State machine finishes instantly with empty cleanup plan
      expect(body.userId).toBe('user123');
    });

    it('should return 404 if key not found', async () => {
      const response = await app.inject({
        method: 'DELETE',
        url: '/key/shred',
        payload: { userId: 'nonexistentuser' },
      });

      expect(response.statusCode).toBe(404);
    });

    it('should handle double-shredding gracefully', async () => {
      // Shred once
      await app.inject({
        method: 'DELETE',
        url: '/key/shred',
        payload: { userId: 'user123' },
      });

      // Shred again
      const response = await app.inject({
        method: 'DELETE',
        url: '/key/shred',
        payload: { userId: 'user123' },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('CERTIFICATE_ISSUED');
    });
  });

  describe('Milestone 2: Complete Flow', () => {
    it('should encrypt, decrypt, shred, and fail subsequent decrypt', async () => {
      const userId = 'user123';
      const plaintext = 'john.doe@example.com';

      // Step 1: Generate key
      const genResponse = await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId },
      });
      expect(genResponse.statusCode).toBe(201); // Ensure key generation is successful
      expect(mockRegistryStore.get(userId).activeDekId).toBe('v1');

      // Step 2: Encrypt plaintext
      const encryptResponse = await app.inject({
        method: 'POST',
        url: '/encrypt',
        payload: { plaintext, userId },
      });
      expect(encryptResponse.statusCode).toBe(200);
      const { ciphertext } = JSON.parse(encryptResponse.body);
      expect(ciphertext.startsWith('v1:')).toBe(true); // Verify version prefix
      expect(ciphertext).toBeDefined();

      // Step 3: Verify decrypt works
      const decryptResponse1 = await app.inject({
        method: 'POST',
        url: '/decrypt',
        payload: { ciphertext, userId },
      });
      expect(decryptResponse1.statusCode).toBe(200);
      expect(JSON.parse(decryptResponse1.body).plaintext).toBe(plaintext);

      // Step 4: Delete key
      const shredResponse = await app.inject({
        method: 'DELETE',
        url: '/key/shred',
        payload: { userId },
      });
      expect(shredResponse.statusCode).toBe(200);
      expect(JSON.parse(shredResponse.body).status).toBe('CERTIFICATE_ISSUED');

      // Step 5: Verify decrypt fails after shredding
      const decryptResponse2 = await app.inject({
        method: 'POST',
        url: '/decrypt',
        payload: { ciphertext, userId },
      });
      expect(decryptResponse2.statusCode).toBe(404);

    });
  });

  describe('Lineage API Integration Tests', () => {
    const userId = 'user123';

    it('should record a lineage event and then query the deletion plan', async () => {
      // 1. Record a lineage event
      const eventPayload = {
        userId,
        source: 'ingestion-api',
        destination: 'hubspot',
        eventType: 'DATA_MOVEMENT',
        context: { jobId: 'sync-001' }
      };

      const recordResponse = await app.inject({
        method: 'POST',
        url: '/lineage/events',
        payload: eventPayload,
      });

      expect(recordResponse.statusCode).toBe(201);
      const recordBody = JSON.parse(recordResponse.body);
      expect(recordBody.status).toBe('RECORDED');
      expect(recordBody.eventId).toBe('mock-event-id-123');

      // 2. Query user lineage to confirm it's tracked
      const lineageResponse = await app.inject({
        method: 'GET',
        url: `/lineage/user/${userId}`,
      });

      expect(lineageResponse.statusCode).toBe(200);
      const lineageBody = JSON.parse(lineageResponse.body);
      expect(lineageBody.destinations).toHaveLength(1);
      expect(lineageBody.destinations[0].name).toBe('hubspot');

      // 3. Query deletion plan
      const planResponse = await app.inject({
        method: 'GET',
        url: `/lineage/deletion-plan/${userId}`,
      });

      expect(planResponse.statusCode).toBe(200);
      const planBody = JSON.parse(planResponse.body);
      expect(planBody.userId).toBe(userId);
      expect(planBody.impactedDestinations).toContain('hubspot');
      expect(planBody.mathematicalErasure.status).toBe('PENDING');
      expect(planBody.mathematicalErasure.stores).toContain('bigquery');
    });

    it('should tolerate dual casing and scope lineage by X-Tenant-Id', async () => {
      const tenantScopedUser = 'tenant-lineage-user';

      const response = await app.inject({
        method: 'POST',
        url: '/lineage/events',
        headers: { 'x-tenant-id': 'tenant-a' },
        payload: {
          user_id: tenantScopedUser,
          userId: tenantScopedUser,
          source: 'pipeline',
          destination: 'bigquery',
          event_type: 'INGESTED',
          eventType: 'INGESTED',
          operation_id: 'op-tenant-lineage',
          operationId: 'op-tenant-lineage',
          data_classification: 'ENCRYPTED_ONLY',
          dataClassification: 'ENCRYPTED_ONLY',
        },
      });

      expect(response.statusCode).toBe(201);
      const events = mockLineageStore.get(tenantScopedUser) || [];
      expect(events[0]).toMatchObject({
        tenantId: 'tenant-a',
        userId: tenantScopedUser,
        destination: 'bigquery',
      });

      const tenantAResponse = await app.inject({
        method: 'GET',
        url: `/lineage/user/${tenantScopedUser}`,
        headers: { 'x-tenant-id': 'tenant-a' },
      });
      expect(JSON.parse(tenantAResponse.body).destinations).toHaveLength(1);

      const tenantBResponse = await app.inject({
        method: 'GET',
        url: `/lineage/user/${tenantScopedUser}`,
        headers: { 'x-tenant-id': 'tenant-b' },
      });
      expect(JSON.parse(tenantBResponse.body).destinations).toHaveLength(0);
    });

    it('should fall back to Firestore hot-path destinations when BigQuery lineage is empty', async () => {
      const userId = 'hot-path-lineage-user';

      await app.inject({
        method: 'POST',
        url: '/key/generate',
        headers: { 'x-tenant-id': 'tenant-hot-path' },
        payload: { userId },
      });

      const lineageWrite = await app.inject({
        method: 'POST',
        url: '/lineage/events',
        headers: { 'x-tenant-id': 'tenant-hot-path' },
        payload: {
          userId,
          source: 'pipeline',
          destination: 'bigquery:chameleon_dev.stg_users',
          dataClassification: 'ENCRYPTED_ONLY',
        },
      });
      expect(lineageWrite.statusCode).toBe(201);

      mockLineageStore.delete(userId);

      const lineageRead = await app.inject({
        method: 'GET',
        url: `/lineage/user/${userId}`,
        headers: { 'x-tenant-id': 'tenant-hot-path' },
      });

      expect(lineageRead.statusCode).toBe(200);
      expect(JSON.parse(lineageRead.body)).toMatchObject({
        userId,
        tenantId: 'tenant-hot-path',
        readModel: 'firestore-hot-path',
        destinations: [
          { name: 'bigquery:chameleon_dev.stg_users' },
        ],
      });

      const deletionPlan = await app.inject({
        method: 'GET',
        url: `/lineage/deletion-plan/${userId}`,
        headers: { 'x-tenant-id': 'tenant-hot-path' },
      });

      expect(deletionPlan.statusCode).toBe(200);
      expect(JSON.parse(deletionPlan.body).impactedDestinations).toContain('bigquery:chameleon_dev.stg_users');
    });

    it('should accept resource-level GHOST_DATA scanner metadata without updating user hot path', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/lineage/events',
        headers: { 'x-tenant-id': 'tenant-ghost' },
        payload: {
          user_id: 'UNKNOWN',
          source: 'ghost-data-scanner',
          destination: 'bigquery:chameleon_dev.stg_users',
          data_classification: 'GHOST_DATA',
          metadata: {
            resource_id: 'bigquery:chameleon_dev.stg_users',
            column: 'email',
            pattern: 'EMAIL',
            count: 2,
            scanner: 'ghost-data-scanner',
          },
        },
      });

      expect(response.statusCode).toBe(201);

      const events = mockLineageStore.get('UNKNOWN') || [];
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        tenantId: 'tenant-ghost',
        userId: 'UNKNOWN',
        source: 'ghost-data-scanner',
        destination: 'bigquery:chameleon_dev.stg_users',
        context: {
          resource_id: 'bigquery:chameleon_dev.stg_users',
          column: 'email',
          pattern: 'EMAIL',
          count: 2,
          scanner: 'ghost-data-scanner',
        },
      });
      expect(mockHotPathDestinationStore.get('UNKNOWN')).toBeUndefined();
    });

    it('should include compact ghost-data summaries in deletion plans without raw PII', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/lineage/events',
        headers: { 'x-tenant-id': 'tenant-ghost-plan' },
        payload: {
          user_id: 'UNKNOWN',
          source: 'ghost-data-scanner',
          destination: 'bigquery:chameleon_dev.stg_users',
          data_classification: 'GHOST_DATA',
          metadata: {
            resource_id: 'bigquery:chameleon_dev.stg_users',
            column: 'email',
            pattern: 'EMAIL',
            count: 2,
            scanner: 'ghost-data-scanner',
          },
        },
      });
      expect(response.statusCode).toBe(201);

      const plan = await app.inject({
        method: 'GET',
        url: '/lineage/deletion-plan/user-with-resource-ghosts',
        headers: { 'x-tenant-id': 'tenant-ghost-plan' },
      });

      expect(plan.statusCode).toBe(200);
      const body = JSON.parse(plan.body);
      expect(body.ghostDataSummary).toEqual([
        expect.objectContaining({
          scope: 'RESOURCE_LEVEL',
          resourceId: 'bigquery:chameleon_dev.stg_users',
          column: 'email',
          pattern: 'EMAIL',
          count: 2,
          scanner: 'ghost-data-scanner',
        }),
      ]);
      expect(JSON.stringify(body)).not.toContain('@');
    });

    it('should accept k6 pipeline lineage events classified as PII', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/lineage/events',
        headers: { 'x-tenant-id': 'tenant-a' },
        payload: {
          event_type: 'DATA_PROVISIONED_TO_SINK',
          eventType: 'DATA_PROVISIONED_TO_SINK',
          tenant_id: 'tenant-a',
          user_id: 'k6-user-299',
          userId: 'k6-user-299',
          source: 'pii-ingestion-worker',
          destination: 'bigquery.stg_users',
          data_classification: 'PII',
          dataClassification: 'PII',
          operation_id: 'k6-op-55',
          operationId: 'k6-op-55',
          metadata: {
            runner: 'k6',
            scenario: 'lineage_events',
          },
        },
      });

      expect(response.statusCode).toBe(201);
      const events = mockLineageStore.get('k6-user-299') || [];
      expect(events[0]).toMatchObject({
        tenantId: 'tenant-a',
        userId: 'k6-user-299',
        destination: 'bigquery.stg_users',
        context: {
          runner: 'k6',
          scenario: 'lineage_events',
        },
      });
      expect(mockHotPathDestinationStore.get('k6-user-299')).toEqual([
        { tenantId: 'tenant-a', destination: 'bigquery.stg_users' },
      ]);
    });

    it('should return 404 for deletion plan if user has no lineage history', async () => {
      const response = await app.inject({ 
        method: 'GET',
        url: '/lineage/deletion-plan/unknown-user',
      });
 
      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('User not found in lineage graph');
    });

    it('should automatically record a lineage event when a key is shredded (Phase 3d verification)', async () => {
      const shredUserId = 'shred-verification-user';

      // 1. Generate key
      await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: shredUserId },
      });

      // Record movement to trigger Janitor (ensures non-empty cleanup plan)
      await app.inject({
        method: 'POST',
        url: '/lineage/events',
        payload: {
          userId: shredUserId,
          source: 'test-source',
          destination: 'hubspot',
          eventType: 'DATA_MOVEMENT',
        },
      });

      // 2. Shred the key
      const shredResponse = await app.inject({
        method: 'DELETE',
        url: '/key/shred',
        payload: { userId: shredUserId },
      });

      expect(shredResponse.statusCode).toBe(200);

      // 3. Verify event was recorded in BigQuery mock
      const userEvents = mockLineageStore.get(shredUserId) || [];
      expect(userEvents.length).toBeGreaterThanOrEqual(3); // KEY_CREATED, DATA_MOVEMENT, KEY_SHREDDED, JANITOR_TRIGGERED

      const keyShreddedEvent = userEvents.find((lineageEvent) => lineageEvent.eventType === 'KEY_SHREDDED');
      expect(keyShreddedEvent).toBeDefined();
      expect(keyShreddedEvent.source).toBe('key-vault');
      expect(keyShreddedEvent.destination).toBe('key-registry');
      expect(keyShreddedEvent.context.status).toBe('KEY_SHREDDED');

      const janitorTriggeredEvent = userEvents.find((lineageEvent) => lineageEvent.eventType === 'JANITOR_TRIGGERED');
      expect(janitorTriggeredEvent).toBeDefined();
      expect(janitorTriggeredEvent.source).toBe('key-vault');
      expect(janitorTriggeredEvent.destination).toBe('janitor-service');
    });

    it('should record audit lineage events for key generation and encryption', async () => {
      const auditUserId = 'audit-verification-user';

      await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: auditUserId },
      });

      await app.inject({
        method: 'POST',
        url: '/encrypt',
        payload: {
          userId: auditUserId,
          plaintext: 'audit@example.com',
        },
      });

      const userEvents = mockLineageStore.get(auditUserId);
      expect(userEvents?.map((event) => event.destination)).toEqual([
        'key-registry',
        'encryption-audit',
      ]); // Ensure both events are recorded
    });
  });

  describe('Batch Key Vault endpoints', () => {
    it('POST /keys/batch-generate should accept tenantId in the body with X-Tenant-Id header', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/keys/batch-generate',
        headers: { 'x-tenant-id': 'tenant-batch' },
        payload: { tenantId: 'tenant-batch', userIds: ['batch-user-1', 'batch-user-2'] },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.processed).toBe(2);
      expect(body.results.map((result: any) => result.status)).toEqual(['GENERATED', 'GENERATED']);
    });

    it('POST /keys/batch-encryption-context should return contexts for pipelines', async () => {
      await app.inject({
        method: 'POST',
        url: '/keys/batch-generate',
        headers: { 'x-tenant-id': 'tenant-batch' },
        payload: { tenantId: 'tenant-batch', userIds: ['batch-context-1', 'batch-context-2'] },
      });

      const response = await app.inject({
        method: 'POST',
        url: '/keys/batch-encryption-context',
        headers: { 'x-tenant-id': 'tenant-batch' },
        payload: { tenantId: 'tenant-batch', userIds: ['batch-context-1', 'batch-context-2'] },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.processed).toBe(2);
      expect(body.results).toHaveLength(2);
      expect(body.contexts).toHaveLength(2);
      expect(body.contexts[0]).toMatchObject({
        userId: 'batch-context-1',
        keyId: 'v1',
        algorithm: 'AES-256-GCM',
        status: 'ACTIVE',
      });
      expect(body.contextsByUserId['batch-context-1'].encryptedDek).toBeDefined();
      expect(body.contexts_by_user_id['batch-context-2'].encrypted_dek).toBeDefined();
    });
  });

  describe('GET /key/:userId/encryption-context', () => {
    it('should return encryption context for an active key', async () => {
      await app.inject({
        method: 'POST',
        url: '/key/generate',
        payload: { userId: 'user-context' },
      });

      const response = await app.inject({
        method: 'GET',
        url: '/key/user-context/encryption-context',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.userId).toBe('user-context');
      expect(body.keyId).toBe('v1');
      expect(body.encryptedDek).toBeDefined();
      expect(body.algorithm).toBe('AES-256-GCM');
      expect(body.encryption_version).toBe('v1');
      expect(body.tokenization).toEqual({ 
        algorithm: 'HMAC-SHA256', 
        tokenKeyId: 'chameleon-token-key-v1',
        token_key_id: 'chameleon-token-key-v1' 
      });
      expect(body.status).toBe('ACTIVE');
    });

    it('should return 404 if key not found or shredded', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/key/nonexistent/encryption-context',
      });
      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.body).error).toContain('User key not found or has been shredded');
    });
  });

  describe('POST /key/rotate', () => {
    const userId = 'user-to-rotate';
    const initialDek = DeterministicAES.generateRandomDEK();
    const newDek = DeterministicAES.generateRandomDEK();
  
    beforeEach(async () => {
      // Mock initial key generation
      mockRegistryStore.set(userId, {
        deks: { v1: initialDek.toString('base64') },
        activeDekId: 'v1',
        status: 'ACTIVE',
        encryptionVersion: 'v2', // New default
        tokenization: { algorithm: 'HMAC-SHA256', tokenKeyId: 'chameleon-token-key-v1' },
        encryptionVersion: 'v1', // Old version for testing rotation
        tokenization: { algorithm: 'HMAC-SHA256', tokenKeyId: 'chameleon-token-key-v1' },
        createdAt: new Date(),
      });
      // Mock the KMS client to return a predictable new DEK (encrypted)
      mockGenerateAndEncryptDek.mockResolvedValue(newDek);
    });

    it('should successfully rotate a user key', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/key/rotate',
        payload: { userId },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('ROTATED');
      expect(body.userId).toBe(userId);

      // Verify registry state
      const registryEntry = mockRegistryStore.get(userId);
      expect(registryEntry.activeDekId).toBe('v2');
      expect(registryEntry.deks.v1).toBe(initialDek.toString('base64'));
      expect(registryEntry.deks.v2).toBe(newDek.toString('base64'));
      expect(registryEntry.rotatedAt).toBeInstanceOf(Date);

      // Verify lineage event
      const userEvents = mockLineageStore.get(userId);
      expect(userEvents).toBeDefined();
      const rotationEvent = userEvents!.find(e => e.destination === 'key-rotation-audit');
      expect(rotationEvent).toBeDefined();
      expect(rotationEvent.context.newVersionId).toBe('v2');
    });

    it('should return 404 if user key not found', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/key/rotate',
        payload: { userId: 'nonexistent-user' },
      });

      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('User key not found or shredded'); // Updated error message
    });

    it('should return 404 if user key is shredded', async () => {
      mockRegistryStore.set(userId, {
        deks: { v1: initialDek.toString('base64') },
        activeDekId: 'v1',
        status: 'SHREDDED',
        encryptionVersion: 'v1',
        tokenization: { algorithm: 'HMAC-SHA256', tokenKeyId: 'chameleon-token-key-v1' },
        createdAt: new Date(),
        shredAt: new Date(),
      });

      const response = await app.inject({
        method: 'POST',
        url: '/key/rotate',
        payload: { userId },
      });

      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('User key not found or shredded'); // Updated error message
    });

    it('should allow encryption with new key and decryption with old key after rotation', async () => {
      // Perform rotation
      await app.inject({ method: 'POST', url: '/key/rotate', payload: { userId } });

      // Encrypt with new active key (v2)
      const encryptResponse = await app.inject({ method: 'POST', url: '/encrypt', payload: { plaintext: 'new data', userId } });
      expect(encryptResponse.statusCode).toBe(200);
      const { ciphertext: newCiphertext } = JSON.parse(encryptResponse.body);
      expect(newCiphertext.startsWith('v2:')).toBe(true);

      // Decrypt old data (encrypted with v1)
      const oldCiphertext = `v1:${DeterministicAES.encrypt('old data', userId, initialDek).ciphertext}`;
      const decryptOldResponse = await app.inject({ method: 'POST', url: '/decrypt', payload: { ciphertext: oldCiphertext, userId } });
      expect(decryptOldResponse.statusCode).toBe(200);
      expect(JSON.parse(decryptOldResponse.body).plaintext).toBe('old data');

      // Decrypt new data (encrypted with v2)
      const decryptNewResponse = await app.inject({ method: 'POST', url: '/decrypt', payload: { ciphertext: newCiphertext, userId } });
      expect(decryptNewResponse.statusCode).toBe(200);
      expect(JSON.parse(decryptNewResponse.body).plaintext).toBe('new data');
    });
  });

  describe('Deletion Request State Machine', () => {
    const userId = 'user123';
    const operationId = '00000000-0000-0000-0000-000000000001';

    beforeEach(async () => {
      await app.inject({ method: 'POST', url: '/key/generate', payload: { userId } });
    });

    it('should create a deletion request', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/deletion-requests',
        payload: { userId, operationId }
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.id).toBe(operationId);
      expect(body.status).toBe('SHRED_REQUESTED');
    });

    it('should get a deletion request', async () => {
      await app.inject({ method: 'POST', url: '/deletion-requests', payload: { userId, operationId } });

      const response = await app.inject({
        method: 'GET',
        url: `/deletion-requests/${operationId}`
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).id).toBe(operationId);
    });

    it('should advance a deletion request status', async () => {
      await app.inject({ method: 'POST', url: '/deletion-requests', payload: { userId, operationId } });

      const advanceOpId = '00000000-0000-0000-0000-000000000002';
      const response = await app.inject({
        method: 'POST',
        url: `/deletion-requests/${operationId}/advance`,
        payload: { newStatus: 'KEY_DESTROYED', operationId: advanceOpId }
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).status).toBe('KEY_DESTROYED');

      // Verify key is destroyed in registry (registry mock marks as SHREDDED/DELETED)
      const statusResponse = await app.inject({ method: 'GET', url: `/key-status/${userId}` });
      expect(JSON.parse(statusResponse.body).status).toBe('SHREDDED');
    });

    it('should not return a deletion request created under a different tenant', async () => {
      await app.inject({
        method: 'POST',
        url: '/deletion-requests',
        headers: { 'x-tenant-id': 'tenant-a' },
        payload: { userId, operationId }
      });

      const response = await app.inject({
        method: 'GET',
        url: `/deletion-requests/${operationId}`,
        headers: { 'x-tenant-id': 'tenant-b' }
      });

      expect(response.statusCode).toBe(404);
    });
  });

});

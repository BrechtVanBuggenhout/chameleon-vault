import { jest, describe, it, expect, beforeEach } from '@jest/globals';

// Mocks for ESM compatibility
const mockLineageData = {
  userId: 'user123',
  destinations: [
    { name: 'hubspot', lastSeen: '2026-06-01T12:00:00Z' },
    { name: 'salesforce', lastSeen: '2026-06-02T08:00:00Z' },
    { name: 'unknown-tool', lastSeen: '2026-06-02T09:00:00Z' }
  ]
};

const mockKeyStatus = {
  userId: 'user123',
  destinations: ['hubspot', 'salesforce', 'unknown-tool']
};

await jest.unstable_mockModule('../src/gcp/firestore-registry.js', () => ({
  FirestoreRegistry: class {
    getKeyStatus = jest.fn(async () => mockKeyStatus);
  }
}));

await jest.unstable_mockModule('../src/gcp/bigquery-lineage.js', () => ({
  BigQueryLineageRepository: class {
    getUserLineage = jest.fn(async () => mockLineageData);
    recordEvent = jest.fn(async () => 'event-123');
  }
}));

await jest.unstable_mockModule('../src/gcp/pubsub-dlq-client.js', () => ({
  PubSubDLQClient: class {
    publishFailedWipe = jest.fn().mockResolvedValue('message-id-123');
  }
}));

await jest.unstable_mockModule('../src/config/env.js', () => ({ // Ensure this mock is comprehensive
  getRequiredEnv: jest.fn((key: string) => {
    switch (key) {
      case 'GCP_PROJECT_ID': return 'test-project';
      case 'CLOUD_KMS_REGION': return 'us-central1';
      case 'CLOUD_KMS_KEY_RING': return 'test-keyring';
      case 'CLOUD_KMS_KEY_NAME': return 'test-key';
      case 'CLOUD_KMS_SIGNING_KEY_RING': return 'test-signing-keyring';
      case 'CLOUD_KMS_SIGNING_KEY_NAME': return 'test-signing-key';
      case 'FIRESTORE_COLLECTION': return 'user_keys';
      case 'FIRESTORE_DELETION_REQUEST_COLLECTION': return 'deletion_requests';
      default: return 'mock-value';
    }
  }),
}));

await jest.unstable_mockModule('../src/logging/index.js', () => ({
  createLogger: () => ({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  }),
}));

const mockWipe = jest.fn();
await jest.unstable_mockModule('../src/services/registry.js', () => ({
  connectorRegistry: {
    getConnector: jest.fn((name: string) => {
      if (name.toLowerCase() === 'hubspot' || name.toLowerCase() === 'salesforce') {
        return { name, wipe: mockWipe };
      }
      return undefined;
    })
  }
}));

await jest.unstable_mockModule('../src/gcp/cloud-kms.js', () => ({
  CloudKMSClient: class {
    asymmetricSign = jest.fn().mockResolvedValue(Buffer.from('mock-signature'));
  }
}));

const { FirestoreRegistry } = await import('../src/gcp/firestore-registry.js');
const { BigQueryLineageRepository } = await import('../src/gcp/bigquery-lineage.js');
const { PubSubDLQClient } = await import('../src/gcp/pubsub-dlq-client.js');
const { CloudKMSClient } = await import('../src/gcp/cloud-kms.js');
const { JanitorService } = await import('../src/services/janitor.js');

describe('JanitorService Integration Tests', () => {
  let janitor: any;
  let mockRegistry: any;
  let mockLineage: any;
  let mockKms: any;
  let mockDlq: any;

  beforeEach((): void => {
    process.env.CLOUD_KMS_SIGNING_KEY_NAME = 'projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1';
    mockRegistry = new (FirestoreRegistry as any)();
    mockLineage = new (BigQueryLineageRepository as any)();
    mockDlq = new (PubSubDLQClient as any)();
    mockKms = new (CloudKMSClient as any)();
    janitor = new JanitorService(mockRegistry, mockLineage, mockKms, mockDlq);
    mockWipe.mockClear();
    // Reduce retry delay for faster test execution
    (janitor as any).MAX_RETRIES = 2;
  });

  it('should create a cleanup plan only for destinations with valid connectors', async () => {
    const tasks = await janitor.createCleanupPlan('user123');
    expect(tasks).toHaveLength(2);
    const destinations = tasks.map((t: any) => t.destination.toLowerCase());
    expect(destinations).toContain('hubspot');
    expect(destinations).toContain('salesforce');
    expect(destinations).not.toContain('unknown-tool');
  });

  it('should process cleanup successfully for all registered destinations', async () => {
    mockWipe.mockResolvedValue({ success: true, timestamp: new Date().toISOString() });

    const results = await janitor.processCleanup('user123');

    expect(results).toHaveLength(2);
    expect(results[0].status).toBe('COMPLETE');
    expect(results[1].status).toBe('COMPLETE');
    expect(mockWipe).toHaveBeenCalledTimes(2);
  });

  it('should retry on transient failures and eventually succeed', async () => {
    mockWipe
      .mockResolvedValueOnce({ success: false, error: 'Network Error' }) // hubspot attempt 1
      .mockResolvedValueOnce({ success: true })                        // hubspot attempt 2 (success)
      .mockResolvedValueOnce({ success: true });                       // salesforce attempt 1

    const results = await janitor.processCleanup('user123');

    const hubspotResult = results.find((r: any) => r.destination === 'hubspot');
    expect(hubspotResult.status).toBe('COMPLETE');
    expect(hubspotResult.attempts).toBe(2);
    expect(mockWipe).toHaveBeenCalledTimes(3);
  });

  it('should mark as FAILED if all retries are exhausted', async () => {
    mockWipe.mockResolvedValue({ success: false, error: 'Persistent API Error' });

    const results = await janitor.processCleanup('user123');

    expect(results.every((r: any) => r.status === 'FAILED')).toBe(true);
    // MAX_RETRIES is set to 2 in beforeEach for each task
    expect(mockWipe).toHaveBeenCalledTimes(4);
  }, 10000);

  it('treats a connector that throws (instead of returning success:false) as a retryable failure, never escaping processCleanup', async () => {
    // A hung connection with no axios timeout, a DNS failure, or any other
    // unexpected error class would surface this way -- processCleanup must
    // convert it into a normal failed-attempt result, not let it reject and
    // take down the caller's Promise.all (see deletion-request-service.ts).
    mockWipe.mockRejectedValue(new Error('connect ETIMEDOUT'));

    const results = await janitor.processCleanup('user123');

    expect(results).toHaveLength(2);
    expect(results.every((r: any) => r.status === 'FAILED')).toBe(true);
    // Still retried like any other failure -- MAX_RETRIES is 2 in beforeEach.
    expect(mockWipe).toHaveBeenCalledTimes(4);
  }, 10000);

  it('treats a connector that throws on only one attempt then succeeds the same as a normal transient failure', async () => {
    mockWipe
      .mockRejectedValueOnce(new Error('socket hang up'))
      .mockResolvedValueOnce({ success: true })
      .mockResolvedValueOnce({ success: true });

    const results = await janitor.processCleanup('user123');

    const hubspotResult = results.find((r: any) => r.destination === 'hubspot');
    expect(hubspotResult.status).toBe('COMPLETE');
    expect(hubspotResult.attempts).toBe(2);
  });

  // Real bug found and fixed this session: this repo's own connectors
  // (hubspot-connector.ts, salesforce-connector.ts) already classify
  // retryable: true/false from the real HTTP status they saw -- janitor.ts
  // used to ignore that field entirely and re-derive a broken version from
  // the error message text (case-sensitive substring checks that matched
  // neither connector's real message format), so every failure got zero
  // backoff regardless of whether it was actually transient, while a
  // permanently-broken auth failure still got hammered for all
  // MAX_RETRIES attempts back-to-back with no delay at all.
  it('stops after a single attempt on a connector-classified non-retryable failure (e.g. real 401/403), never retries', async () => {
    mockWipe.mockResolvedValue({
      success: false,
      destination: 'hubspot',
      error: 'Authentication failed',
      retryable: false,
    });

    const results = await janitor.processCleanup('user123');

    const hubspotResult = results.find((r: any) => r.destination === 'hubspot');
    expect(hubspotResult.status).toBe('FAILED');
    expect(hubspotResult.attempts).toBe(1);
    // Both destinations are non-retryable here -- 1 call each, not
    // MAX_RETRIES (2) each. The old code always attempted MAX_RETRIES
    // times regardless of retryable, just without a delay in between.
    expect(mockWipe).toHaveBeenCalledTimes(2);
  });

  it('still retries a connector-classified retryable failure (e.g. real 429/5xx) up to MAX_RETRIES', async () => {
    mockWipe.mockResolvedValue({
      success: false,
      destination: 'hubspot',
      error: 'Rate limited',
      retryable: true,
    });

    const results = await janitor.processCleanup('user123');

    expect(results.every((r: any) => r.status === 'FAILED')).toBe(true);
    // MAX_RETRIES is 2 in beforeEach, for each of the 2 destinations.
    expect(mockWipe).toHaveBeenCalledTimes(4);
  }, 10000);

  it('a real HubSpot-shaped auth failure and a real Salesforce-shaped rate-limit failure are each handled by their own actual classification, not a shared misclassification', async () => {
    // Mirrors exactly what hubspot-connector.ts and salesforce-connector.ts
    // themselves actually return -- not a synthetic shape.
    mockWipe
      .mockResolvedValueOnce({ success: false, destination: 'hubspot', error: 'Request failed with status code 401', retryable: false })
      .mockResolvedValueOnce({ success: false, destination: 'salesforce', error: 'Rate limited', retryable: true })
      .mockResolvedValueOnce({ success: true, destination: 'salesforce' });

    const results = await janitor.processCleanup('user123');

    const hubspotResult = results.find((r: any) => r.destination === 'hubspot');
    const salesforceResult = results.find((r: any) => r.destination === 'salesforce');
    expect(hubspotResult.status).toBe('FAILED');
    expect(hubspotResult.attempts).toBe(1);
    expect(salesforceResult.status).toBe('COMPLETE');
    expect(salesforceResult.attempts).toBe(2);
  });
});
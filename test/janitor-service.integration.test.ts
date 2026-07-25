import { jest, describe, it, expect, beforeEach } from '@jest/globals';

// 1. Mock GCP Dependencies for ESM
await jest.unstable_mockModule('../src/gcp/firestore-registry.js', () => ({
  FirestoreRegistry: class {
    getKeyStatus = jest.fn();
  }
}));
await jest.unstable_mockModule('../src/gcp/bigquery-lineage.js', () => ({
  BigQueryLineageRepository: class {
    recordEvent = jest.fn().mockResolvedValue('mock-event-id' as any);
  }
}));
await jest.unstable_mockModule('../src/gcp/cloud-kms.js', () => ({
  CloudKMSClient: class {
    asymmetricSign = jest.fn().mockResolvedValue('mock-signature' as any);
  }
}));
await jest.unstable_mockModule('../src/gcp/pubsub-dlq-client.js', () => ({
  PubSubDLQClient: class {
    publishFailedWipe = jest.fn().mockResolvedValue('msg-123' as any);
  }
}));

// 2. Import Janitor and Registry
const { JanitorService } = await import('../src/services/janitor.js');
const { FirestoreRegistry } = await import('../src/gcp/firestore-registry.js');

describe('JanitorService - Cleanup Plan Logic', () => {
  let janitorService: any;
  let mockRegistry: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockRegistry = new FirestoreRegistry('test-project', 'test-collection');
    janitorService = new JanitorService(
      mockRegistry,
      { recordEvent: jest.fn() } as any,
      {} as any,
      {} as any
    );
  });

  it('should only include destinations in the cleanup plan that have registered connectors', async () => {
    const userId = 'user-123';
    const tenantId = 'tenant-abc';

    // Mock Firestore to return multiple destinations
    (mockRegistry.getKeyStatus as jest.Mock).mockResolvedValue({
      status: 'ACTIVE',
      destinations: ['hubspot', 'salesforce', 'unsupported-mystery-saas']
    });

    // Act
    const tasks = await janitorService.createCleanupPlan(userId, tenantId);

    // Assert
    // We expect 2 tasks because HubSpot and Salesforce are registered in registry.ts, 
    // but 'unsupported-mystery-saas' is not.
    expect(tasks).toHaveLength(2);
    const destinations = tasks.map((t: any) => t.destination);
    expect(destinations).toContain('hubspot');
    expect(destinations).toContain('salesforce');
    expect(destinations).not.toContain('unsupported-mystery-saas');
    
    expect(tasks[0]).toMatchObject({
      userId: 'user-123',
      status: 'PENDING',
      attempts: 0
    });
  });

  it('should return an empty plan if the user has no tracked destinations', async () => {
    (mockRegistry.getKeyStatus as jest.Mock).mockResolvedValue({
      status: 'ACTIVE',
      destinations: []
    });

    const tasks = await janitorService.createCleanupPlan('clean-user', 'tenant-a');
    expect(tasks).toEqual([]);
  });

  it('should correctly pass the tenantId to the Firestore lookup', async () => {
    (mockRegistry.getKeyStatus as jest.Mock).mockResolvedValue(null);
    
    await janitorService.createCleanupPlan('user-id', 'specific-tenant');
    
    expect(mockRegistry.getKeyStatus).toHaveBeenCalledWith('user-id', 'specific-tenant');
  });
});

import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import * as avsc from 'avsc';

// 1. Define all mock functions for both BigQuery and Pub/Sub
const mockPublishMessage = jest.fn();
const mockTopic = jest.fn(() => ({ publishMessage: mockPublishMessage }));
const mockPubSub = jest.fn().mockImplementation(() => ({
  topic: mockTopic,
}));

const mockQuery = jest.fn();
const mockBigQuery = jest.fn().mockImplementation((options: any) => ({
  query: mockQuery,
  projectId: options?.projectId || process.env.GCP_PROJECT_ID || 'test-project',
}));

// 2. Register module mocks BEFORE imports
await jest.unstable_mockModule('@google-cloud/pubsub', () => ({
  PubSub: mockPubSub,
  default: { PubSub: mockPubSub },
}));

await jest.unstable_mockModule('@google-cloud/bigquery', () => ({
  BigQuery: mockBigQuery,
  default: { BigQuery: mockBigQuery },
}));

// Mock logger to keep test outputs clean
await jest.unstable_mockModule('../src/logging/index.js', () => ({
  createLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }),
}));

// 3. Set baseline environment variables
process.env.GCP_PROJECT_ID = 'test-project';
process.env.BIGQUERY_DATASET_ID = 'test_dataset';
process.env.LINEAGE_TOPIC_ID = 'projects/test-project/topics/lineage-events';

// 4. Import the repository cleanly
const { BigQueryLineageRepository } = await import('../src/gcp/bigquery-lineage.js');

const Type = (avsc as any).Type || (avsc as any).default?.Type;
const deployedLineageEventSchema = Type.forSchema({
  fields: [
    { name: 'event_id', type: 'string' },
    { name: 'tenant_id', type: ['null', 'string'], default: null },
    { name: 'user_id', type: 'string' },
    { name: 'source', type: 'string' },
    { name: 'destination', type: 'string' },
    { name: 'timestamp', type: { type: 'long', logicalType: 'timestamp-micros' } },
    { name: 'context', type: 'string' },
  ],
  name: 'LineageEvent',
  type: 'record',
});

describe('BigQueryLineageRepository', () => {
  let repository: InstanceType<typeof BigQueryLineageRepository>;

  beforeEach(() => {
    jest.clearAllMocks();

    // Re-establish env setup for isolation
    process.env.GCP_PROJECT_ID = 'test-project';
    process.env.BIGQUERY_DATASET_ID = 'test_dataset';
    process.env.LINEAGE_TOPIC_ID = 'projects/test-project/topics/lineage-events';

    mockPublishMessage.mockResolvedValue('message-id-123' as never);

    repository = new BigQueryLineageRepository();
  });

  describe('recordEvent', () => {
    it('should successfully publish a lineage event to Pub/Sub', async () => {
      const eventId = await repository.recordEvent({
        userId: 'user123',
        source: 'ingestion-api',
        destination: 'bigquery-raw',
      });

      // Verifies a ULID was successfully returned
      expect(eventId).toBeDefined();
      expect(typeof eventId).toBe('string');

      // Verifies that Pub/Sub was routed to the right topic
      expect(mockTopic).toHaveBeenCalledWith('projects/test-project/topics/lineage-events');
      expect(mockPublishMessage).toHaveBeenCalledTimes(1);

      // Verifies that a binary buffer data packet was passed to publishMessage
      const callArgs = mockPublishMessage.mock.calls[0][0] as { data: Buffer };
      expect(callArgs.data).toBeInstanceOf(Buffer);

      const decoded = deployedLineageEventSchema.fromBuffer(callArgs.data);
      expect(decoded).toEqual(
        expect.objectContaining({
          tenant_id: 'default-tenant',
          user_id: 'user123',
          source: 'ingestion-api',
          destination: 'bigquery-raw',
        }),
      );
      expect(typeof decoded.timestamp).toBe('number');
      expect(Number.isInteger(decoded.timestamp)).toBe(true);
      expect(decoded.timestamp).toBeGreaterThan(1_700_000_000_000_000);
    });

    it('should handle Pub/Sub publish failure gracefully and still return a ULID', async () => {
      // Simulate Pub/Sub failing
      mockPublishMessage.mockRejectedValueOnce(new Error('Pub/Sub error') as never);

      const eventId = await repository.recordEvent({
        userId: 'user123',
        source: 's',
        destination: 'd',
      });

      // The repository catches errors and falls back to logging, so it should still succeed
      expect(eventId).toBeDefined();
      expect(typeof eventId).toBe('string');
      expect(mockPublishMessage).toHaveBeenCalledTimes(1);
    });
  });

  describe('getUserLineage', () => {
    it('should return mapped lineage data for a specific user from BigQuery', async () => {
      mockQuery.mockResolvedValueOnce([
        [
          { name: 'hubspot', lastSeen: { value: '2026-05-30T12:00:00Z' } },
          { name: 'salesforce', lastSeen: { value: '2026-05-29T10:00:00Z' } },
        ],
      ] as never);

      const result = await repository.getUserLineage('user123');

      expect(result.userId).toBe('user123');
      expect(result.destinations).toHaveLength(2);
      expect(result.destinations[0].name).toBe('hubspot');
      expect(result.destinations[0].lastSeen).toBeInstanceOf(Date);

      expect(mockQuery).toHaveBeenCalledWith(
        expect.objectContaining({
          query: expect.stringContaining('FROM `test-project.test_dataset.events`'),
          params: { userId: 'user123', tenantId: 'default-tenant' },
        }),
      );
    });

    it('should return empty destinations if no records are found', async () => {
      mockQuery.mockResolvedValueOnce([[]] as never);

      const result = await repository.getUserLineage('unknown-user');

      expect(result).toEqual({
        userId: 'unknown-user',
        destinations: [],
      });
    });
  });

  describe('getGhostDataFindings', () => {
    it('should map compact ghost-data summaries from BigQuery', async () => {
      mockQuery.mockResolvedValueOnce([
        [
          {
            user_id: 'UNKNOWN',
            source: 'ghost-data-scanner',
            destination: 'bigquery:chameleon_dev.stg_users',
            resource_id: 'bigquery:chameleon_dev.stg_users',
            system: 'bigquery',
            column_name: 'email',
            pattern: 'EMAIL',
            finding_count: 2,
            confidence: 0.98,
            scanner: 'ghost-data-scanner',
            last_seen: { value: '2026-06-17T18:00:00Z' },
          },
        ],
      ] as never);

      const result = await repository.getGhostDataFindings('user123', 'tenant-a');

      expect(result).toEqual([
        {
          scope: 'RESOURCE_LEVEL',
          resourceId: 'bigquery:chameleon_dev.stg_users',
          system: 'bigquery',
          column: 'email',
          pattern: 'EMAIL',
          count: 2,
          confidence: 0.98,
          scanner: 'ghost-data-scanner',
          lastSeen: '2026-06-17T18:00:00Z',
        },
      ]);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.objectContaining({
          query: expect.stringContaining('GHOST_DATA'),
          params: { userId: 'user123', tenantId: 'tenant-a' },
        }),
      );
    });
  });
});

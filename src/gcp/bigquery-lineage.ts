import { PubSub } from '@google-cloud/pubsub';
import { BigQuery } from '@google-cloud/bigquery';
import * as avsc from 'avsc';
import type { GhostDataSummary, ILineageRepository, LineageEvent, UserLineage, WarehouseDiscoveryFinding } from '../types/lineage.js';
import { createLogger } from '../logging/index.js';
import { ulid } from 'ulid';

const logger = createLogger('bigquery-lineage');

export class BigQueryLineageRepository implements ILineageRepository {
  private pubsub: PubSub;
  private bq: BigQuery;
  private topicId: string;
  private avroType: any;

  constructor() {
    this.pubsub = new PubSub();
    this.bq = new BigQuery();
    this.topicId = process.env.LINEAGE_TOPIC_ID || '';
    
    if (!this.topicId) {
      logger.warn('LINEAGE_TOPIC_ID is not set. Lineage events will fallback to stdout logging.');
    } else {
      logger.info({ topicId: this.topicId }, 'Lineage repository initialized with Pub/Sub Hot-Path');
    }

    // Initialize Avro Schema for Hot-Path Binary Encoding.
    // This must exactly match the Pub/Sub topic schema, including union types.
    const schema = {
      fields: [
        { name: "event_id", type: "string" },
        { name: "tenant_id", type: ["null", "string"], default: null },
        { name: "user_id", type: "string" },
        { name: "source", type: "string" },
        { name: "destination", type: "string" },
        { name: "timestamp", type: { type: "long", logicalType: "timestamp-micros" } },
        { name: "context", type: "string" }
      ],
      name: "LineageEvent",
      type: "record"
    };

    // Resiliently resolve the Type function from the CommonJS module
    const Type = (avsc as any).Type || (avsc as any).default?.Type;
    if (!Type) {
      logger.error('Failed to load avsc Type constructor. Lineage reporting will fail.');
      return;
    }
    this.avroType = Type.forSchema(schema);
  }

  async recordEvent(event: Omit<LineageEvent, 'eventId' | 'timestamp'>): Promise<string> {
    const eventId = ulid();
    const timestampMicros = Date.now() * 1000;

    // Prepare payload aligned with Avro schema
    // Metadata fields are packed into the 'context' JSON string to fit the 6-field infra schema
    // Defensive casting to String ensures we never pass undefined to a 'string' Avro type
    const avroPayload = {
      event_id: String(eventId),
      tenant_id: String(event.tenantId || (event as any).tenant_id || 'default-tenant'),
      user_id: String(event.userId || event.user_id || (event as any).user_id || 'UNKNOWN'),
      source: String(event.source || 'UNKNOWN'),
      destination: String(event.destination || 'UNKNOWN'),
      timestamp: timestampMicros,
      context: JSON.stringify({
        event_type: event.eventType || event.event_type || 'UNKNOWN',
        operation_id: event.operationId || event.operation_id || eventId,
        deletion_request_id: event.deletionRequestId || event.deletion_request_id || 'NONE',
        data_classification: event.dataClassification || event.data_classification || 'UNKNOWN',
        retention_policy: event.retentionPolicy || event.retention_policy || 'UNKNOWN',
        ...(event.context || event.metadata || {})
      })
    };

    try {
      if (!this.topicId || !this.avroType) {
        throw new Error(`Lineage misconfigured: topicId=${!!this.topicId}, avroType=${!!this.avroType}`);
      }

      // avsc.toBuffer() returns the raw binary encoding required by Pub/Sub
      const dataBuffer = Buffer.from(this.avroType.toBuffer(avroPayload));
      await this.pubsub.topic(this.topicId).publishMessage({ data: dataBuffer });

      logger.info({ 
        eventId, 
        topic: this.topicId, 
        payload: avroPayload 
      }, 'Lineage event successfully published to Pub/Sub');
    } catch (error) {
      logger.error({ error, eventId }, 'Failed to publish lineage event to Pub/Sub. Falling back to structured logging.');
      // Fallback to structured logging to prevent data loss during Pub/Sub outages
      logger.info({ ...avroPayload, eventType: 'LINEAGE_EVENT' }, 'Lineage event logged (Pub/Sub fallback)');
    }

    return eventId;
  }

  async getUserLineage(userId: string, tenantId: string = 'default-tenant'): Promise<UserLineage> {
    // This method is now "Cold Path" only (Audit).
    // Real-time operations should use the Hot Path (Firestore Data Map).
    logger.info({ userId }, 'Querying BigQuery for user lineage summary');
    
    const datasetId = process.env.BIGQUERY_DATASET_ID || 'lineage_db';
    const tableId = 'events'; // Matches lineage_table_id's default in chameleon-infra-gcp/variables.tf
    
    const query = `
      SELECT 
        destination as name, 
        MAX(timestamp) as lastSeen
      FROM \`${this.bq.projectId}.${datasetId}.${tableId}\`
      WHERE user_id = @userId AND tenant_id = @tenantId
      GROUP BY destination
      ORDER BY lastSeen DESC
    `;

    try {
      const [rows] = await this.bq.query({
        query,
        params: { userId, tenantId },
      });

      return {
        userId,
        destinations: rows.map(row => ({ ...row, lastSeen: new Date(row.lastSeen.value) }))
      };
    } catch (error) {
      logger.error({ error, userId }, 'Failed to query BigQuery lineage');
      return { userId, destinations: [] };
    }
  }

  async getGhostDataFindings(userId: string, tenantId: string = 'default-tenant'): Promise<GhostDataSummary[]> {
    const datasetId = process.env.BIGQUERY_DATASET_ID || 'lineage_db';
    const tableId = 'events';

    const query = `
      SELECT
        user_id,
        source,
        destination,
        COALESCE(
          JSON_VALUE(context, '$.resource_id'),
          JSON_VALUE(metadata, '$.resource_id'),
          destination
        ) AS resource_id,
        COALESCE(
          JSON_VALUE(context, '$.system'),
          JSON_VALUE(metadata, '$.system'),
          SPLIT(destination, ':')[SAFE_OFFSET(0)]
        ) AS system,
        COALESCE(JSON_VALUE(context, '$.column'), JSON_VALUE(metadata, '$.column')) AS column_name,
        COALESCE(JSON_VALUE(context, '$.pattern'), JSON_VALUE(metadata, '$.pattern')) AS pattern,
        SAFE_CAST(COALESCE(JSON_VALUE(context, '$.count'), JSON_VALUE(metadata, '$.count')) AS INT64) AS finding_count,
        SAFE_CAST(COALESCE(JSON_VALUE(context, '$.confidence'), JSON_VALUE(metadata, '$.confidence')) AS FLOAT64) AS confidence,
        COALESCE(JSON_VALUE(context, '$.scanner'), JSON_VALUE(metadata, '$.scanner'), source) AS scanner,
        MAX(timestamp) AS last_seen
      FROM \`${this.bq.projectId}.${datasetId}.${tableId}\`
      WHERE tenant_id = @tenantId
        AND (user_id = @userId OR user_id = 'UNKNOWN')
        AND COALESCE(data_classification, JSON_VALUE(context, '$.data_classification')) = 'GHOST_DATA'
      GROUP BY user_id, source, destination, resource_id, system, column_name, pattern, finding_count, confidence, scanner
      ORDER BY last_seen DESC
      LIMIT 50
    `;

    try {
      const [rows] = await this.bq.query({
        query,
        params: { userId, tenantId },
      });

      return rows.map((row) => ({
        scope: row.user_id === 'UNKNOWN' ? 'RESOURCE_LEVEL' : 'USER_LINKED',
        resourceId: row.resource_id || row.destination,
        system: row.system || row.destination,
        column: row.column_name || undefined,
        pattern: row.pattern || undefined,
        count: typeof row.finding_count === 'number' ? row.finding_count : undefined,
        confidence: typeof row.confidence === 'number' ? row.confidence : undefined,
        scanner: row.scanner || undefined,
        lastSeen: row.last_seen?.value || row.last_seen || new Date().toISOString(),
      }));
    } catch (error) {
      logger.error({ error, userId, tenantId }, 'Failed to query BigQuery ghost data findings');
      return [];
    }
  }

  /**
   * Returns the latest WAREHOUSE_METADATA_DISCOVERED event per resource that the crawler
   * flagged UNREGISTERED or DRIFTED — the undeclared tables surfaced in the Console's
   * "declare" workflow. Metadata only (column names, never values). Deduped to the most
   * recent event per resource.
   */
  async getWarehouseDiscoveryFindings(tenantId: string = 'default-tenant'): Promise<WarehouseDiscoveryFinding[]> {
    const datasetId = process.env.BIGQUERY_DATASET_ID || 'lineage_db';
    const tableId = 'events';

    const query = `
      WITH discovered AS (
        SELECT
          COALESCE(JSON_VALUE(context, '$.resource_id'), JSON_VALUE(metadata, '$.resource_id'), destination) AS resource_id,
          COALESCE(JSON_VALUE(context, '$.system'), JSON_VALUE(metadata, '$.system'), 'bigquery') AS system,
          COALESCE(JSON_VALUE(context, '$.dataset_id'), JSON_VALUE(metadata, '$.dataset_id')) AS dataset_id,
          COALESCE(JSON_VALUE(context, '$.table_id'), JSON_VALUE(metadata, '$.table_id')) AS table_id,
          COALESCE(JSON_VALUE(context, '$.registry_status'), JSON_VALUE(metadata, '$.registry_status')) AS registry_status,
          COALESCE(JSON_QUERY(context, '$.new_columns'), JSON_QUERY(metadata, '$.new_columns')) AS new_columns,
          COALESCE(JSON_VALUE(context, '$.recommended_action'), JSON_VALUE(metadata, '$.recommended_action')) AS recommended_action,
          timestamp,
          ROW_NUMBER() OVER (
            PARTITION BY COALESCE(JSON_VALUE(context, '$.resource_id'), JSON_VALUE(metadata, '$.resource_id'), destination)
            ORDER BY timestamp DESC
          ) AS rn
        FROM \`${this.bq.projectId}.${datasetId}.${tableId}\`
        WHERE tenant_id = @tenantId
          AND COALESCE(JSON_VALUE(context, '$.event_type'), JSON_VALUE(metadata, '$.event_type')) = 'WAREHOUSE_METADATA_DISCOVERED'
      )
      SELECT resource_id, system, dataset_id, table_id, registry_status, new_columns, recommended_action, timestamp AS last_seen
      FROM discovered
      WHERE rn = 1 AND registry_status IN ('UNREGISTERED', 'DRIFTED')
      ORDER BY last_seen DESC
      LIMIT 100
    `;

    try {
      const [rows] = await this.bq.query({ query, params: { tenantId } });
      return rows.map((row) => {
        let columns: string[] = [];
        try {
          columns = row.new_columns ? (JSON.parse(row.new_columns) as string[]) : [];
        } catch {
          columns = [];
        }
        return {
          resourceId: row.resource_id,
          system: row.system || 'bigquery',
          datasetId: row.dataset_id || undefined,
          tableId: row.table_id || undefined,
          registryStatus: (row.registry_status || 'UNREGISTERED') as 'UNREGISTERED' | 'DRIFTED',
          columns,
          recommendedAction: row.recommended_action || undefined,
          lastSeen: row.last_seen?.value || row.last_seen || new Date().toISOString(),
        };
      });
    } catch (error) {
      logger.error({ error, tenantId }, 'Failed to query warehouse discovery findings');
      return [];
    }
  }
}

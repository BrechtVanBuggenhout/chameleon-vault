import { BigQuery } from '@google-cloud/bigquery';
import { createLogger } from '../logging/index.js';

const logger = createLogger('bigquery-schema-service');

export interface DiscoveredColumn {
  name: string;
  dataType: string;
  nullable: boolean;
  ordinalPosition: number;
}

export class InvalidResourceIdError extends Error {}

/**
 * Parses a `bigquery:project.dataset.table` resourceId into its parts.
 * Thrown message doubles as the 400 response body — keep it user-facing.
 */
export function parseBigQueryResourceId(resourceId: string): { projectId: string; datasetId: string; tableId: string } {
  const match = /^bigquery:([^.]+)\.([^.]+)\.([^.]+)$/.exec(resourceId);
  if (!match) {
    throw new InvalidResourceIdError(
      `"${resourceId}" is not a bigquery resource ID in the form bigquery:project.dataset.table.`
    );
  }
  const [, projectId, datasetId, tableId] = match;
  return { projectId, datasetId, tableId };
}

/**
 * Live schema introspection so the Declare form can offer real columns to
 * pick from instead of asking someone to type them from memory. Read-only —
 * only ever queries INFORMATION_SCHEMA.COLUMNS, never table data itself, so
 * this only needs bigquery.metadataViewer, not dataViewer.
 */
export class BigQuerySchemaService {
  private readonly bq: BigQuery;

  constructor(projectId: string) {
    this.bq = new BigQuery({ projectId });
  }

  async getColumns(resourceId: string): Promise<DiscoveredColumn[]> {
    const { projectId, datasetId, tableId } = parseBigQueryResourceId(resourceId);

    const query = `
SELECT column_name, data_type, is_nullable, ordinal_position
FROM \`${projectId}.${datasetId}\`.INFORMATION_SCHEMA.COLUMNS
WHERE table_name = @tableId
ORDER BY ordinal_position
`;

    try {
      const [rows] = await this.bq.query({ query, params: { tableId } });
      return (rows as Record<string, unknown>[]).map((row) => ({
        name: String(row.column_name),
        dataType: String(row.data_type),
        nullable: row.is_nullable === 'YES',
        ordinalPosition: Number(row.ordinal_position),
      }));
    } catch (error) {
      logger.error({ error, resourceId }, 'Failed to read BigQuery schema');
      throw error;
    }
  }

  /**
   * BigQuery's table_type from INFORMATION_SCHEMA.TABLES -- 'BASE TABLE',
   * 'VIEW', 'MATERIALIZED VIEW', or 'EXTERNAL'. Used to reject
   * REDACT_IN_PLACE against anything that isn't a real, writable table:
   * BigQuery's UPDATE DML flatly refuses to run against a VIEW (confirmed
   * live: "... is not allowed for this operation because it currently has
   * type VIEW"), which a customer would otherwise only discover the first
   * time a real deletion actually tries to redact it. Returns null if the
   * table/view can't be found at all, distinct from a real type string.
   */
  async getTableType(resourceId: string): Promise<string | null> {
    const { projectId, datasetId, tableId } = parseBigQueryResourceId(resourceId);

    const query = `
SELECT table_type
FROM \`${projectId}.${datasetId}\`.INFORMATION_SCHEMA.TABLES
WHERE table_name = @tableId
`;

    try {
      const [rows] = await this.bq.query({ query, params: { tableId } });
      const row = (rows as Record<string, unknown>[])[0];
      return row ? String(row.table_type) : null;
    } catch (error) {
      logger.error({ error, resourceId }, 'Failed to read BigQuery table type');
      throw error;
    }
  }
}

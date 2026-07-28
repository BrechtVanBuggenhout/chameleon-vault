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
}

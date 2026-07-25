import type { ConnectionOptions } from 'snowflake-sdk';
import { createLogger } from '../logging/index.js';
import { SnowflakeClient } from './client.js';
import {
  assemblePiiRegistryEntries,
  type IPiiRegistryRepository,
  type LineageRow,
  type RegistryRow,
} from '../gcp/pii-registry-repository.js';
import type { PiiRegistryEntry } from '../types/pii-registry.js';

const logger = createLogger('snowflake-pii-registry-repository');

/**
 * Same role as BigQueryPiiRegistryRepository, for the same `pii_registry` /
 * `pii_field_lineage` tables when the chameleon_pii dbt package was built
 * against a Snowflake target instead. Shares the pure assembly logic
 * (`assemblePiiRegistryEntries`) with the BigQuery reader — only the
 * warehouse client and SQL dialect differ.
 */
export class SnowflakePiiRegistryRepository implements IPiiRegistryRepository {
  private readonly client: SnowflakeClient;
  private readonly database: string;
  private readonly schema: string;

  constructor(options: ConnectionOptions & { database: string; schema: string }) {
    this.database = options.database;
    this.schema = options.schema;
    this.client = new SnowflakeClient(options);
  }

  async loadEntries(): Promise<PiiRegistryEntry[]> {
    const [registryRows, lineageRows] = await Promise.all([this.queryRegistry(), this.queryLineage()]);
    const entries = assemblePiiRegistryEntries(registryRows, lineageRows);

    if (entries.length > 0) {
      logger.info(
        { resourceCount: entries.length, fieldCount: registryRows.length },
        'Loaded PII registry from dbt-produced Snowflake tables'
      );
    }
    return entries;
  }

  private async queryRegistry(): Promise<RegistryRow[]> {
    const query = `SELECT
        resource_id, model_name, system, resource_layer, owner,
        field_name, classification, handling, confidence, detection_method,
        required_in_mart, registry_version
      FROM ${this.database}.${this.schema}.pii_registry`;
    return this.client.query<RegistryRow>(query);
  }

  private async queryLineage(): Promise<LineageRow[]> {
    try {
      const query = `SELECT source_resource_id, field_name, downstream_model, hops
        FROM ${this.database}.${this.schema}.pii_field_lineage`;
      return await this.client.query<LineageRow>(query);
    } catch (error) {
      // Lineage is enrichment only — a missing table should not block the registry.
      logger.warn({ error }, 'pii_field_lineage unavailable; continuing without lineage evidence');
      return [];
    }
  }
}

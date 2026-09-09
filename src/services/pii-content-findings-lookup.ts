import { BigQuery } from '@google-cloud/bigquery';
import { parseBigQueryResourceId } from '../gcp/bigquery-schema-service.js';

export interface ContentConfirmedFinding {
  resourceId: string;
  columnName: string;
  jsonPath: string;
  classification: string;
  pattern: string;
  matchCount: number;
  sampledRows: number;
  scannedAt: string;
}

/**
 * Reads chameleon-pii-dbt's own `pii_content_findings` table -- the one
 * ghost-data-adjacent finding type that actually inspected real column
 * VALUES, not just column names/schema (see WarehouseDiscoveryFinding,
 * sourced from a pure INFORMATION_SCHEMA crawl that never reads a single
 * row). A `json_path IS NOT NULL` row is a Stage 2 (path-level) finding --
 * chameleon-pii-dbt's scan_content.sql macro deliberately skips path-level
 * detection for any JSON key BigQuery's JSON_VALUE/JSON_QUERY can't safely
 * address (a key with a space/apostrophe/etc -- confirmed live against
 * real BigQuery, see that macro's own _is_safe_dotted_json_path), so a
 * real JSON-column finding can legitimately have no path at all. This
 * class only ever returns rows where a path IS known -- "content
 * confirmed, but we can't say exactly where" isn't yet worth surfacing at
 * this precision tier; the coarser WarehouseDiscoveryFinding tier already
 * covers "something's here, undeclared" for that case.
 */
export class PiiContentFindingsLookupService {
  private readonly projectId: string;
  private readonly datasetId: string;
  private readonly tableId: string;

  constructor(private readonly bq: BigQuery, contentFindingsResourceId: string) {
    const parsed = parseBigQueryResourceId(contentFindingsResourceId);
    this.projectId = parsed.projectId;
    this.datasetId = parsed.datasetId;
    this.tableId = parsed.tableId;
  }

  /**
   * The latest scan's path-level findings. No tenant_id filter -- this
   * table has no such column (it's a dbt model scanning this deployment's
   * own BigQuery project directly; the project boundary itself is the
   * tenant boundary here, unlike lineage_db.events' shared multi-tenant
   * event log). Undeclared-resource filtering happens at the call site
   * (pii-registry.ts's /discovery route), same as WarehouseDiscoveryFinding
   * -- this method returns every real path-level finding, full stop.
   */
  async getPathLevelFindings(): Promise<ContentConfirmedFinding[]> {
    const query = [
      'SELECT',
      "  CONCAT(system, ':', table_catalog, '.', table_schema, '.', table_name) AS resource_id,",
      '  column_name, json_path, classification, pattern, match_count, sampled_rows, scanned_at',
      `FROM \`${this.projectId}.${this.datasetId}.${this.tableId}\``,
      'WHERE json_path IS NOT NULL',
      'ORDER BY scanned_at DESC',
      'LIMIT 200',
    ].join('\n');

    const [rows] = await this.bq.query({ query });
    return rows.map((row) => ({
      resourceId: row.resource_id,
      columnName: row.column_name,
      jsonPath: row.json_path,
      classification: row.classification,
      pattern: row.pattern,
      matchCount: Number(row.match_count),
      sampledRows: Number(row.sampled_rows),
      scannedAt:
        typeof row.scanned_at?.value === 'string'
          ? row.scanned_at.value
          : new Date(row.scanned_at).toISOString(),
    }));
  }
}

import { BigQuery } from '@google-cloud/bigquery';
import { parseBigQueryResourceId } from '../gcp/bigquery-schema-service.js';

export interface PiiVaultLookupParams {
  tenantId: string;
  userId: string;
  resourceId: string;
  fieldName: string;
}

/**
 * Looks up a single pii_vault row's raw ciphertext -- the ad-hoc decrypt
 * route's read path. Distinct from DecryptedViewService (only ever
 * generates SQL for a persistent BigQuery view; never queries pii_vault
 * from Node itself) and from SourceRedactionService (writes to a
 * customer's own source table, never reads pii_vault row-by-row).
 */
export class PiiVaultLookupService {
  private readonly piiVaultProjectId: string;
  private readonly piiVaultDatasetId: string;
  private readonly piiVaultTableId: string;

  constructor(private readonly bq: BigQuery, piiVaultResourceId: string) {
    const parsed = parseBigQueryResourceId(piiVaultResourceId);
    this.piiVaultProjectId = parsed.projectId;
    this.piiVaultDatasetId = parsed.datasetId;
    this.piiVaultTableId = parsed.tableId;
  }

  /**
   * Returns the most recently synced raw ciphertext
   * (key_id:iv_b64:ciphertext_b64) for one user+resource+field, or null if
   * no such row exists -- covers "field was never declared/synced" and
   * "user has no data for this resource" identically, matching this API's
   * existing convention of never leaking *why* a value is unavailable.
   */
  async findCiphertext(params: PiiVaultLookupParams): Promise<string | null> {
    const [rows] = await this.bq.query({
      query: [
        'SELECT CAST(encrypted_value AS STRING) AS raw_ciphertext',
        `FROM \`${this.piiVaultProjectId}.${this.piiVaultDatasetId}.${this.piiVaultTableId}\``,
        'WHERE tenant_id = @tenantId AND user_id = @userId AND resource_id = @resourceId AND field_name = @fieldName',
        'ORDER BY synced_at DESC',
        'LIMIT 1',
      ].join('\n'),
      params: {
        tenantId: params.tenantId,
        userId: params.userId,
        resourceId: params.resourceId,
        fieldName: params.fieldName,
      },
    });
    const row = (rows as { raw_ciphertext: string | null }[])[0];
    return row?.raw_ciphertext ?? null;
  }
}

import { BigQuery } from '@google-cloud/bigquery';
import { parseBigQueryResourceId } from '../gcp/bigquery-schema-service.js';
import { PiiRegistryService } from './pii-registry-service.js';
import type { PiiRegistryEntry } from '../types/pii-registry.js';
import { assertSafeIdentifiers } from './sql-identifier-safety.js';
import { buildPiiVaultPivotColumns, escapeSqlStringLiteral } from './pii-vault-pivot-sql.js';
import { hasSourceRedactionStrategy } from './source-redaction-strategies.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('source-redaction-service');

export interface SourceRedactionResult {
  resourceId: string;
  success: boolean;
  rowsAffected?: number;
  error?: string;
}

/**
 * Executes the three implemented source-redaction strategies for manually-
 * declared resources -- what (if anything) happens to a customer's own
 * source table when a user is deleted, distinct from crypto-shredding
 * Chameleon's own copy (pii_vault). Independently combinable per resource
 * (see resolveSourceRedactionStrategies/hasSourceRedactionStrategy) -- a
 * single resource can run any subset of the three.
 *
 * REDACT_IN_PLACE (redactUserInDeclaredSources): triggered per deletion, as
 * part of the deletion cascade -- nulls out exactly the declared PII
 * columns for one user's rows, never deletes rows, never touches any other
 * column.
 *
 * SHADOW_COPY (ensureShadowCopy): NOT a cascade step. Unlike REDACT_IN_PLACE,
 * a shadow copy is a live BigQuery view created once (at declare time) that
 * joins the source table's own non-PII columns against pii_vault's live-
 * decrypted fields -- reusing the exact same never-materializes-plaintext
 * mechanism DecryptedViewService already ships. Once created, the view
 * naturally reflects every future deletion on every query, forever, with no
 * per-deletion action needed -- the underlying decrypt call simply starts
 * failing (returning NULL) for a shredded user's rows, exactly like an
 * ad-hoc decrypted view already does.
 *
 * ENCRYPTED_COPY (ensureEncryptedCopyTable / deleteUserFromEncryptedCopies):
 * declare-time table creation (like SHADOW_COPY) PLUS a real per-deletion
 * cascade step (like REDACT_IN_PLACE). Maintains a physical, append-only
 * `{table}_encrypted_raw` table -- populated by chameleon-data-pipelines'
 * chunked sync, same insert_rows_json mechanism as pii_vault itself, holding
 * the same reversible key_id:iv_b64:ciphertext_b64 bundle pii_vault stores --
 * and a deduplicating view `{table}_encrypted` on top of it
 * (QUALIFY ROW_NUMBER() ... = 1), which is what downstream dbt models
 * actually reference. On deletion, the row is genuinely DELETEd from the raw
 * table (not just left to a view's decrypt-fails-silently behavior like
 * SHADOW_COPY), since the whole point is that the ciphertext itself must
 * stop existing once the key is shredded, not merely stop resolving.
 *
 * Deliberately separate from JanitorService/ConnectorRegistry: those model
 * a fixed set of globally-registered SaaS destinations (one connector
 * instance per system, e.g. "hubspot"), not an open-ended, per-declaration
 * set of customer-owned BigQuery tables each with their own table name and
 * column names taken from the registry entry itself.
 */
export class SourceRedactionService {
  private readonly piiVault?: { projectId: string; datasetId: string; tableId: string };

  constructor(
    private readonly registryService: PiiRegistryService,
    private readonly bq: BigQuery,
    // Same pii_vault + batch-decrypt function DecryptedViewService already
    // uses -- SHADOW_COPY reuses that exact mechanism rather than inventing
    // a second decrypt path. Both optional and independent of
    // REDACT_IN_PLACE, which never touches pii_vault at all: a deployment
    // can have decrypted views (and therefore SHADOW_COPY) disabled while
    // still using REDACT_IN_PLACE, and vice versa.
    piiVaultResourceId?: string,
    private readonly batchDecryptFunctionRef?: string
  ) {
    this.piiVault = piiVaultResourceId ? parseBigQueryResourceId(piiVaultResourceId) : undefined;
  }

  // --- REDACT_IN_PLACE (deletion-cascade-triggered) ---

  /**
   * Cheap, side-effect-free lookup of which manually-declared resources this
   * tenant has opted into REDACT_IN_PLACE for -- mirrors
   * JanitorService.createCleanupPlan()'s plan/execute split, so the deletion
   * state machine can decide whether there's any redaction work to do at
   * all before committing to the CASCADE_PENDING path.
   */
  planRedaction(tenantId: string): PiiRegistryEntry[] {
    return this.registryService
      .listEntries({ tenantId, ownerConnector: 'manual' })
      .filter((entry) => hasSourceRedactionStrategy(entry, 'REDACT_IN_PLACE'));
  }

  /**
   * Redacts this user's declared PII fields in every resource planRedaction()
   * finds. Returns one result per attempted resource so the caller (deletion-
   * request-service.ts) can gate certificate issuance on every one
   * succeeding, exactly like the existing SaaS janitor cascade already does.
   */
  async redactUserInDeclaredSources(userId: string, tenantId: string): Promise<SourceRedactionResult[]> {
    const resources = this.planRedaction(tenantId);
    if (resources.length === 0) {
      return [];
    }

    const results: SourceRedactionResult[] = [];
    for (const resource of resources) {
      try {
        const rowsAffected = await this.redactOne(resource, userId, tenantId);
        results.push({ resourceId: resource.resourceId, success: true, rowsAffected });
        logger.info(
          { resourceId: resource.resourceId, userId, rowsAffected },
          'Redacted declared PII fields in source table'
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        results.push({ resourceId: resource.resourceId, success: false, error: message });
        logger.error({ err: error, resourceId: resource.resourceId, userId }, 'Source redaction failed');
      }
    }
    return results;
  }

  private async redactOne(resource: PiiRegistryEntry, userId: string, tenantId: string): Promise<number> {
    if (resource.system !== 'bigquery') {
      throw new Error(`sourceRedactionStrategy REDACT_IN_PLACE is only implemented for bigquery resources, got "${resource.system}".`);
    }
    if (!resource.userIdColumn) {
      // Should be unreachable -- buildManualEntry already requires this at
      // declare time -- but this executes a real write, so fail loudly
      // rather than silently skipping the WHERE clause.
      throw new Error('Resource has no userIdColumn declared; refusing to redact without a safe scope.');
    }

    const fieldsToRedact = resource.piiFields.map((f) => f.name);
    if (fieldsToRedact.length === 0) {
      throw new Error('Resource has no declared piiFields to redact.');
    }

    assertSafeIdentifiers([resource.userIdColumn, resource.tenantIdColumn, ...fieldsToRedact].filter(
      (v): v is string => v !== undefined
    ));

    const { projectId, datasetId, tableId } = parseBigQueryResourceId(resource.resourceId);
    const setClause = fieldsToRedact.map((field) => `${field} = NULL`).join(', ');
    const whereParts = [`${resource.userIdColumn} = @userId`];
    const params: Record<string, string> = { userId };
    if (resource.tenantIdColumn) {
      whereParts.push(`${resource.tenantIdColumn} = @tenantId`);
      params.tenantId = tenantId;
    }

    const query = `UPDATE \`${projectId}.${datasetId}.${tableId}\` SET ${setClause} WHERE ${whereParts.join(' AND ')}`;

    const [job] = await this.bq.createQueryJob({ query, params });
    await job.getQueryResults();
    const [metadata] = await job.getMetadata();
    return Number(metadata?.statistics?.query?.numDmlAffectedRows ?? 0);
  }

  // --- SHADOW_COPY (declare-time-triggered, not a cascade step) ---

  private shadowViewId(tableId: string): string {
    return `${tableId}_deidentified`;
  }

  /**
   * Called whenever a manual resource is declared or updated (see
   * routes/pii-registry.ts). If the resource is opted into SHADOW_COPY,
   * (re)creates the deidentified view alongside the source table. If it
   * isn't (including if it never was), drops any existing shadow view for
   * it -- covers both "never had one" (a cheap no-op 404) and "just turned
   * it off" (a real cleanup).
   */
  async ensureShadowCopy(resource: PiiRegistryEntry): Promise<void> {
    if (!hasSourceRedactionStrategy(resource, 'SHADOW_COPY')) {
      await this.dropShadowCopyIfExists(resource);
      return;
    }
    if (!this.piiVault || !this.batchDecryptFunctionRef) {
      throw new Error(
        'SHADOW_COPY requires decrypted views to be enabled on this deployment (pii_vault + batch-decrypt function not configured).'
      );
    }
    if (resource.system !== 'bigquery') {
      throw new Error(`sourceRedactionStrategy SHADOW_COPY is only implemented for bigquery resources, got "${resource.system}".`);
    }
    if (!resource.userIdColumn) {
      throw new Error('Resource has no userIdColumn declared; refusing to build a shadow copy without a safe join key.');
    }
    if (!resource.tenantId) {
      // Unreachable for a real manual entry (upsertEntry already requires
      // this), but this generates a literal into SQL, so fail loudly.
      throw new Error('Resource has no tenantId; refusing to build a shadow copy.');
    }

    // Only ENCRYPT-handling fields are ever actually synced into pii_vault
    // as field_name rows (see chameleon-data-pipelines' pii_vault_sync.py) --
    // e.g. a HASH_SURROGATE field never appears there. Pivoting a
    // non-ENCRYPT field would always resolve to NULL, and worse, if a
    // customer happens to name one identically to a column this view
    // already selects (confirmed live: a declared field literally named
    // "user_id"), it collides with the CTE's own `user_id` column and
    // BigQuery rejects the whole view with an ambiguous-GROUP-BY error
    // before it can silently NULL that column out instead.
    const fields = resource.piiFields.filter((f) => f.handling === 'ENCRYPT').map((f) => f.name);
    if (fields.length === 0) {
      throw new Error('Resource has no ENCRYPT-handling piiFields to shadow-copy (only ENCRYPT fields are ever synced into pii_vault).');
    }

    assertSafeIdentifiers([resource.userIdColumn, resource.tenantIdColumn, ...fields].filter(
      (v): v is string => v !== undefined
    ));

    const { projectId, datasetId, tableId } = parseBigQueryResourceId(resource.resourceId);
    const viewId = this.shadowViewId(tableId);
    const pivotColumns = buildPiiVaultPivotColumns(fields, this.batchDecryptFunctionRef);
    const exceptClause = fields.join(', ');
    const decryptedColumns = fields.map((field) => `d.${field}`).join(', ');
    const tenantLiteral = escapeSqlStringLiteral(resource.tenantId);
    const tenantFilter = resource.tenantIdColumn ? `WHERE s.${resource.tenantIdColumn} = '${tenantLiteral}'` : '';

    const viewSql = [
      'WITH decrypted_pii AS (',
      '  SELECT',
      '    user_id,',
      `    ${pivotColumns.join(',\n    ')}`,
      `  FROM \`${this.piiVault.projectId}.${this.piiVault.datasetId}.${this.piiVault.tableId}\``,
      `  WHERE tenant_id = '${tenantLiteral}'`,
      '  GROUP BY user_id',
      ')',
      `SELECT s.* EXCEPT (${exceptClause}), ${decryptedColumns}`,
      `FROM \`${projectId}.${datasetId}.${tableId}\` s`,
      `LEFT JOIN decrypted_pii d ON s.${resource.userIdColumn} = d.user_id`,
      tenantFilter,
    ]
      .filter((line) => line !== '')
      .join('\n');

    // Re-declaring an existing shadow view (e.g. after the customer adds a
    // new PII field) needs replace, not insert-only, semantics -- delete-
    // then-create is simpler and more clearly correct than juggling the
    // BigQuery client's metadata-patch API, and matches the same
    // idempotent-cleanup pattern revokeView() below already uses.
    await this.dropShadowCopyIfExists(resource);
    await this.bq.dataset(datasetId, { projectId }).createTable(viewId, { view: viewSql });

    logger.info({ resourceId: resource.resourceId, viewId }, 'Shadow-copy deidentified view created');
  }

  async dropShadowCopyIfExists(resource: PiiRegistryEntry): Promise<void> {
    if (resource.system !== 'bigquery') {
      return;
    }
    const { projectId, datasetId, tableId } = parseBigQueryResourceId(resource.resourceId);
    const viewId = this.shadowViewId(tableId);
    try {
      await this.bq.dataset(datasetId, { projectId }).table(viewId).delete();
      logger.info({ resourceId: resource.resourceId, viewId }, 'Shadow-copy deidentified view dropped');
    } catch (error) {
      // Already gone (or never created) is fine; anything else is a real
      // failure and shouldn't be swallowed.
      if ((error as { code?: number })?.code !== 404) {
        logger.error({ err: error, resourceId: resource.resourceId, viewId }, 'Failed to drop shadow-copy view');
        throw error;
      }
    }
  }

  // --- ENCRYPTED_COPY (declare-time table creation + deletion-cascade cleanup) ---

  private encryptedCopyRawTableId(tableId: string): string {
    return `${tableId}_encrypted_raw`;
  }

  private encryptedCopyViewId(tableId: string): string {
    return `${tableId}_encrypted`;
  }

  /** Same encrypted-fields filter ensureShadowCopy uses -- see its comment for why. */
  private encryptedFieldsOf(resource: PiiRegistryEntry): string[] {
    return resource.piiFields.filter((f) => f.handling === 'ENCRYPT').map((f) => f.name);
  }

  /**
   * Called whenever a manual resource is declared or updated (see
   * routes/pii-registry.ts), same call site as ensureShadowCopy. If the
   * resource isn't opted into ENCRYPTED_COPY, this is a no-op -- unlike
   * SHADOW_COPY, disabling ENCRYPTED_COPY never drops the raw table or its
   * view; removing an already-materialized ciphertext copy is a deliberate
   * separate admin action, not something a checkbox toggle should do
   * automatically.
   *
   * Idempotent and safe to call on every declare/redeclare: table/view
   * creation use CREATE ... IF NOT EXISTS / CREATE OR REPLACE VIEW, and new
   * PII fields added on a redeclare are picked up via
   * ALTER TABLE ADD COLUMN IF NOT EXISTS rather than requiring the table to
   * be dropped and recreated (which would discard already-synced rows).
   */
  async ensureEncryptedCopyTable(resource: PiiRegistryEntry): Promise<void> {
    if (!hasSourceRedactionStrategy(resource, 'ENCRYPTED_COPY')) {
      return;
    }
    if (resource.system !== 'bigquery') {
      throw new Error(`sourceRedactionStrategy ENCRYPTED_COPY is only implemented for bigquery resources, got "${resource.system}".`);
    }
    if (!resource.userIdColumn) {
      throw new Error('Resource has no userIdColumn declared; refusing to build an encrypted copy without a safe key column.');
    }

    const fields = this.encryptedFieldsOf(resource);
    if (fields.length === 0) {
      throw new Error('Resource has no ENCRYPT-handling piiFields to encrypted-copy (only ENCRYPT fields are ever synced into pii_vault).');
    }

    assertSafeIdentifiers([resource.userIdColumn, resource.tenantIdColumn, ...fields].filter(
      (v): v is string => v !== undefined
    ));

    const { projectId, datasetId, tableId } = parseBigQueryResourceId(resource.resourceId);
    const rawTableId = this.encryptedCopyRawTableId(tableId);
    const viewId = this.encryptedCopyViewId(tableId);
    const sourceRef = `\`${projectId}.${datasetId}.${tableId}\``;
    const rawRef = `\`${projectId}.${datasetId}.${rawTableId}\``;
    const viewRef = `\`${projectId}.${datasetId}.${viewId}\``;

    // Defines the raw table's schema by deriving it from the source table
    // rather than hand-mapping INFORMATION_SCHEMA types -- correct even for
    // array/struct passthrough columns, which a manual type map would get
    // wrong. WHERE FALSE means this never actually copies a row; IF NOT
    // EXISTS makes it a true no-op (BigQuery doesn't even evaluate the
    // SELECT) once the table already exists, so this is safe to run on
    // every redeclare, not just the first one. synced_at is stamped by the
    // writer (chameleon-data-pipelines) on every append and is what the
    // dedup view below orders by.
    const exceptClause = fields.join(', ');
    const nullPiiColumns = fields.map((field) => `CAST(NULL AS STRING) AS ${field}`).join(',\n    ');
    const createTableSql = [
      `CREATE TABLE IF NOT EXISTS ${rawRef} AS`,
      'SELECT',
      `    s.* EXCEPT (${exceptClause}),`,
      `    ${nullPiiColumns},`,
      '    CAST(NULL AS TIMESTAMP) AS synced_at',
      `FROM ${sourceRef} s`,
      'WHERE FALSE',
    ].join('\n');
    const [createJob] = await this.bq.createQueryJob({ query: createTableSql });
    await createJob.getQueryResults();

    // Covers the table-already-existed case: any field declared since the
    // last time this ran. IF NOT EXISTS per-column means already-present
    // fields (including everything the CREATE above just added on a first
    // run) are harmless no-ops.
    const addColumnClauses = fields.map((field) => `ADD COLUMN IF NOT EXISTS ${field} STRING`).join(',\n  ');
    const alterTableSql = `ALTER TABLE ${rawRef}\n  ${addColumnClauses}`;
    const [alterJob] = await this.bq.createQueryJob({ query: alterTableSql });
    await alterJob.getQueryResults();

    const dedupViewSql = [
      `SELECT * FROM ${rawRef}`,
      `QUALIFY ROW_NUMBER() OVER (PARTITION BY ${resource.userIdColumn} ORDER BY synced_at DESC) = 1`,
    ].join('\n');
    await this.bq.dataset(datasetId, { projectId }).createTable(viewId, { view: dedupViewSql }).catch(async (error) => {
      // createTable has no create-or-replace mode; a view that already
      // exists from a prior declare needs an explicit replace via DDL
      // instead of delete-then-create (unlike SHADOW_COPY, there's no
      // dropEncryptedCopyIfExists step to lean on here, since this method
      // never drops on disable).
      if ((error as { code?: number })?.code !== 409) {
        throw error;
      }
      const [viewJob] = await this.bq.createQueryJob({ query: `CREATE OR REPLACE VIEW ${viewRef} AS\n${dedupViewSql}` });
      await viewJob.getQueryResults();
    });

    logger.info({ resourceId: resource.resourceId, rawTableId, viewId }, 'Encrypted-copy raw table and dedup view ensured');
  }

  /** Mirrors planRedaction()'s plan/execute split for the ENCRYPTED_COPY strategy. */
  planEncryptedCopyDeletion(tenantId: string): PiiRegistryEntry[] {
    return this.registryService
      .listEntries({ tenantId, ownerConnector: 'manual' })
      .filter((entry) => hasSourceRedactionStrategy(entry, 'ENCRYPTED_COPY'));
  }

  /**
   * Deletes this user's row from every ENCRYPTED_COPY raw table
   * planEncryptedCopyDeletion() finds -- a real DELETE, not a null-out like
   * REDACT_IN_PLACE, since the whole point of this strategy is that the
   * ciphertext itself must stop existing once the key is shredded. Safe at
   * this volume even though DELETE is DML: unlike a sync chunk's writes,
   * this runs once per individual deletion request, the same low-
   * concurrency profile REDACT_IN_PLACE's UPDATE already runs in production
   * without issue (see this file's class comment on the write-path
   * decision this mirrors).
   */
  async deleteUserFromEncryptedCopies(userId: string, tenantId: string): Promise<SourceRedactionResult[]> {
    const resources = this.planEncryptedCopyDeletion(tenantId);
    if (resources.length === 0) {
      return [];
    }

    const results: SourceRedactionResult[] = [];
    for (const resource of resources) {
      try {
        const rowsAffected = await this.deleteFromEncryptedCopyOne(resource, userId, tenantId);
        results.push({ resourceId: resource.resourceId, success: true, rowsAffected });
        logger.info(
          { resourceId: resource.resourceId, userId, rowsAffected },
          'Deleted user row from encrypted-copy raw table'
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        results.push({ resourceId: resource.resourceId, success: false, error: message });
        logger.error({ err: error, resourceId: resource.resourceId, userId }, 'Encrypted-copy deletion failed');
      }
    }
    return results;
  }

  private async deleteFromEncryptedCopyOne(resource: PiiRegistryEntry, userId: string, tenantId: string): Promise<number> {
    if (resource.system !== 'bigquery') {
      throw new Error(`sourceRedactionStrategy ENCRYPTED_COPY is only implemented for bigquery resources, got "${resource.system}".`);
    }
    if (!resource.userIdColumn) {
      // Should be unreachable -- buildManualEntry already requires this at
      // declare time -- but this executes a real write, so fail loudly
      // rather than silently skipping the WHERE clause.
      throw new Error('Resource has no userIdColumn declared; refusing to delete from encrypted copy without a safe scope.');
    }

    assertSafeIdentifiers([resource.userIdColumn, resource.tenantIdColumn].filter(
      (v): v is string => v !== undefined
    ));

    const { projectId, datasetId, tableId } = parseBigQueryResourceId(resource.resourceId);
    const rawRef = `\`${projectId}.${datasetId}.${this.encryptedCopyRawTableId(tableId)}\``;
    const whereParts = [`${resource.userIdColumn} = @userId`];
    const params: Record<string, string> = { userId };
    if (resource.tenantIdColumn) {
      whereParts.push(`${resource.tenantIdColumn} = @tenantId`);
      params.tenantId = tenantId;
    }

    const query = `DELETE FROM ${rawRef} WHERE ${whereParts.join(' AND ')}`;

    const [job] = await this.bq.createQueryJob({ query, params });
    await job.getQueryResults();
    const [metadata] = await job.getMetadata();
    return Number(metadata?.statistics?.query?.numDmlAffectedRows ?? 0);
  }
}

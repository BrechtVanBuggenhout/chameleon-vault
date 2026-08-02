import { BigQuery, Table } from '@google-cloud/bigquery';
import { parseBigQueryResourceId } from '../gcp/bigquery-schema-service.js';
import { DecryptedViewsRepository } from '../gcp/decrypted-views-repository.js';
import { DecryptedViewDeclaration } from '../types/decrypted-view.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('decrypted-view-service');

const VIEW_NAME_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

export interface DeclareViewInput {
  tenantId: string;
  viewName: string;
  declaredFields: string[];
  businessJustification: string;
  createdBy: string;
  consumerServiceAccount: string;
}

/**
 * Owns the parts of a decrypted view that Terraform can't reconcile: the
 * per-declaration BigQuery view DDL and per-view IAM grant. Terraform
 * (see chameleon-infra-gcp's decrypted_views.tf) stops at the static layer
 * -- the dataset, the connection, the base IAM role -- since it can't
 * manage end-user-triggered, dynamically-named resources.
 *
 * Every decrypted view sources from the central pii_vault table -- never a
 * customer-supplied resource id. There's deliberately no "declare pii_vault
 * as a PII resource first" step: pii_vault_sync.py only ever syncs fields
 * whose ORIGINAL registered handling is literally ENCRYPT (see
 * chameleon-data-pipelines' pii_vault_sync.py, enumerate_resource), so any
 * field_name present in pii_vault at all is already guaranteed to have come
 * from a real crypto anchor -- that classification decision was made once,
 * correctly, at sync time against the field's true source resource. Making
 * someone re-declare pii_vault itself in the registry would just be
 * re-asserting something already true by construction.
 */
export class DecryptedViewService {
  private readonly bq: BigQuery;
  private readonly piiVaultProjectId: string;
  private readonly piiVaultDatasetId: string;
  private readonly piiVaultTableId: string;

  constructor(
    projectId: string,
    private readonly decryptedViewsDataset: string,
    // Fully-qualified BigQuery remote function name, e.g.
    // `project.decrypted_views.chameleon_batch_decrypt` -- the DDL calls
    // this per selected field, it's what actually performs the live,
    // never-persisted decrypt at query time.
    private readonly batchDecryptFunctionRef: string,
    // Fully-qualified resource id of the central pii_vault table, e.g.
    // `bigquery:proj.chameleon_dev.pii_vault` -- the one and only source
    // every decrypted view is built on top of.
    piiVaultResourceId: string,
    private readonly repository: DecryptedViewsRepository
  ) {
    this.bq = new BigQuery({ projectId });
    const parsed = parseBigQueryResourceId(piiVaultResourceId);
    this.piiVaultProjectId = parsed.projectId;
    this.piiVaultDatasetId = parsed.datasetId;
    this.piiVaultTableId = parsed.tableId;
  }

  get piiVaultResourceId(): string {
    return `bigquery:${this.piiVaultProjectId}.${this.piiVaultDatasetId}.${this.piiVaultTableId}`;
  }

  async declareView(input: DeclareViewInput): Promise<DecryptedViewDeclaration> {
    if (!VIEW_NAME_PATTERN.test(input.viewName)) {
      throw new Error('View name must be a valid identifier: letters, numbers, underscores, not starting with a number.');
    }
    if (!input.businessJustification?.trim()) {
      throw new Error('businessJustification is required.');
    }
    if (input.declaredFields.length === 0) {
      throw new Error('At least one declared field is required.');
    }

    const available = await this.getAvailableFields(input.tenantId);
    for (const fieldName of input.declaredFields) {
      if (!available.includes(fieldName)) {
        throw new Error(
          `Field "${fieldName}" has no synced rows in pii_vault for this tenant -- check the field name, or that it has actually been synced yet.`
        );
      }
    }

    const viewId = `${input.tenantId}_${input.viewName}`;
    const viewSql = this.buildViewSql(input);

    const dataset = this.bq.dataset(this.decryptedViewsDataset);
    const [view] = await dataset.createTable(viewId, { view: viewSql });
    await this.grantViewerOnView(view, input.consumerServiceAccount);

    logger.info(
      { tenantId: input.tenantId, viewName: input.viewName, viewId },
      'Decrypted view created'
    );

    return this.repository.create({
      tenant_id: input.tenantId,
      view_name: input.viewName,
      source_resource_id: this.piiVaultResourceId,
      declared_fields: input.declaredFields,
      business_justification: input.businessJustification,
      created_by: input.createdBy,
      bigquery_dataset: this.decryptedViewsDataset,
      bigquery_view_name: viewId,
    });
  }

  /**
   * Distinct field_names actually present in pii_vault for a tenant --
   * powers both declareView()'s own validation (catches a typo'd field
   * name, doesn't re-litigate a classification already made at sync time)
   * and the console's field picker (GET /decrypted-views/available-fields),
   * so a customer sees real options instead of needing to know exact
   * field_name strings by heart.
   */
  async getAvailableFields(tenantId: string): Promise<string[]> {
    const [rows] = await this.bq.query({
      query: `SELECT DISTINCT field_name FROM \`${this.piiVaultProjectId}.${this.piiVaultDatasetId}.${this.piiVaultTableId}\` WHERE tenant_id = @tenantId ORDER BY field_name`,
      params: { tenantId },
    });
    return (rows as { field_name: string }[]).map((row) => row.field_name);
  }

  /**
   * pii_vault is long/flattened (one row per user+resource+field:
   * tenant_id, user_id, resource_id, field_name, key_id, token,
   * encrypted_value, synced_at), not one named column per PII field. Each
   * declared field is pivoted out by filtering to its field_name and
   * picking the most recently synced value -- ARRAY_AGG(...ORDER BY
   * synced_at DESC LIMIT 1), not MAX(), since MAX() over decrypted strings
   * has no "most recent" semantics. Only encrypted_value (real, reversible
   * ciphertext) is ever decrypted here -- never token, which is a one-way
   * HMAC join key.
   *
   * WHERE tenant_id = ... is a real correctness requirement, not tidiness:
   * pii_vault is one physical table across every tenant, so an unscoped
   * view here would expose other tenants' rows.
   */
  private buildViewSql(input: DeclareViewInput): string {
    const escapeLiteral = (value: string) => value.replace(/'/g, "''");

    const pivotColumns = input.declaredFields.map((field) => {
      const fieldLiteral = escapeLiteral(field);
      return (
        `ARRAY_AGG(IF(field_name = '${fieldLiteral}', ` +
        `${this.batchDecryptFunctionRef}(CAST(encrypted_value AS STRING), user_id, tenant_id), NULL) ` +
        `IGNORE NULLS ORDER BY synced_at DESC LIMIT 1)[SAFE_OFFSET(0)] AS ${field}`
      );
    });

    return [
      'SELECT',
      '  user_id,',
      '  tenant_id,',
      `  ${pivotColumns.join(',\n  ')}`,
      `FROM \`${this.piiVaultProjectId}.${this.piiVaultDatasetId}.${this.piiVaultTableId}\``,
      `WHERE tenant_id = '${escapeLiteral(input.tenantId)}'`,
      'GROUP BY user_id, tenant_id',
    ].join('\n');
  }

  async revokeView(tenantId: string, viewName: string, revokedBy: string): Promise<DecryptedViewDeclaration | null> {
    const existing = await this.repository.get(tenantId, viewName);
    if (!existing || existing.status !== 'active') {
      return null;
    }

    const dataset = this.bq.dataset(existing.bigquery_dataset);
    try {
      await dataset.table(existing.bigquery_view_name).delete();
    } catch (error) {
      // Already gone is fine (e.g. a prior revoke partially completed);
      // anything else is a real failure and shouldn't be swallowed.
      if ((error as { code?: number })?.code !== 404) {
        logger.error({ error, tenantId, viewName }, 'Failed to drop decrypted view');
        throw error;
      }
    }

    logger.info({ tenantId, viewName, revokedBy }, 'Decrypted view revoked');
    return this.repository.revoke(tenantId, viewName, revokedBy);
  }

  private async grantViewerOnView(view: Table, consumerServiceAccount: string): Promise<void> {
    const [policy] = await view.getIamPolicy();
    const bindings = policy.bindings ?? [];
    const member = `serviceAccount:${consumerServiceAccount}`;
    const viewerBinding = bindings.find((b) => b.role === 'roles/bigquery.dataViewer');
    if (viewerBinding) {
      viewerBinding.members = viewerBinding.members ?? [];
      if (!viewerBinding.members.includes(member)) viewerBinding.members.push(member);
    } else {
      bindings.push({ role: 'roles/bigquery.dataViewer', members: [member] });
    }
    await view.setIamPolicy({ ...policy, bindings });
  }
}

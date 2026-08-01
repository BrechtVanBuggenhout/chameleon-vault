import { BigQuery, Table } from '@google-cloud/bigquery';
import { parseBigQueryResourceId } from '../gcp/bigquery-schema-service.js';
import { DecryptedViewsRepository } from '../gcp/decrypted-views-repository.js';
import { PiiRegistryService } from './pii-registry-service.js';
import { DecryptedViewDeclaration } from '../types/decrypted-view.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('decrypted-view-service');

// Only fields with an actual crypto anchor are eligible -- exposing a
// decrypted view over something already plaintext or handled without
// encryption/tokenization/surrogate defeats the point (see
// chameleon_pii's own pii_shred_readiness, which uses this exact set to
// mean "shreddable").
const SHREDDABLE_HANDLING = new Set(['ENCRYPT', 'TOKENIZE', 'HASH_SURROGATE']);

const VIEW_NAME_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

export interface DeclareViewInput {
  tenantId: string;
  viewName: string;
  sourceResourceId: string;
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
 */
export class DecryptedViewService {
  private readonly bq: BigQuery;

  constructor(
    projectId: string,
    private readonly decryptedViewsDataset: string,
    // Fully-qualified BigQuery remote function name, e.g.
    // `project.decrypted_views.chameleon_batch_decrypt` -- the DDL calls
    // this per selected field, it's what actually performs the live,
    // never-persisted decrypt at query time.
    private readonly batchDecryptFunctionRef: string,
    private readonly repository: DecryptedViewsRepository,
    private readonly registryService: PiiRegistryService
  ) {
    this.bq = new BigQuery({ projectId });
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

    const entry = this.registryService.getEntry(input.sourceResourceId, input.tenantId);
    if (!entry) {
      throw new Error(
        `No registered PII resource found for ${input.sourceResourceId} -- decrypted views can only source from already-declared resources.`
      );
    }
    for (const fieldName of input.declaredFields) {
      const field = entry.piiFields.find((f) => f.name === fieldName);
      if (!field) {
        throw new Error(`Field "${fieldName}" is not declared on ${input.sourceResourceId}.`);
      }
      if (!SHREDDABLE_HANDLING.has(field.handling)) {
        throw new Error(
          `Field "${fieldName}" has handling "${field.handling}" -- only ENCRYPT/TOKENIZE/HASH_SURROGATE fields can be exposed through a decrypted view.`
        );
      }
    }

    const { projectId, datasetId, tableId } = parseBigQueryResourceId(input.sourceResourceId);
    const viewId = `${input.tenantId}_${input.viewName}`;
    const viewSql = this.buildViewSql(input, projectId, datasetId, tableId);

    const dataset = this.bq.dataset(this.decryptedViewsDataset);
    const [view] = await dataset.createTable(viewId, { view: viewSql });
    await this.grantViewerOnView(view, input.consumerServiceAccount);

    logger.info(
      { tenantId: input.tenantId, viewName: input.viewName, sourceResourceId: input.sourceResourceId, viewId },
      'Decrypted view created'
    );

    return this.repository.create({
      tenant_id: input.tenantId,
      view_name: input.viewName,
      source_resource_id: input.sourceResourceId,
      declared_fields: input.declaredFields,
      business_justification: input.businessJustification,
      created_by: input.createdBy,
      bigquery_dataset: this.decryptedViewsDataset,
      bigquery_view_name: viewId,
    });
  }

  /**
   * The source is always the central pii_vault table -- long/flattened
   * (one row per user+resource+field: tenant_id, user_id, resource_id,
   * field_name, key_id, token, encrypted_value, synced_at), not one named
   * column per PII field. Each declared field is pivoted out by filtering
   * to its field_name and picking the most recently synced value --
   * ARRAY_AGG(...ORDER BY synced_at DESC LIMIT 1), not MAX(), since MAX()
   * over decrypted strings has no "most recent" semantics. Only
   * encrypted_value (real, reversible ciphertext) is ever decrypted here --
   * never token, which is a one-way HMAC join key.
   *
   * WHERE tenant_id = ... is a real correctness requirement, not tidiness:
   * pii_vault is one physical table across every tenant, so an unscoped
   * view here would expose other tenants' rows.
   */
  private buildViewSql(input: DeclareViewInput, projectId: string, datasetId: string, tableId: string): string {
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
      `FROM \`${projectId}.${datasetId}.${tableId}\``,
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

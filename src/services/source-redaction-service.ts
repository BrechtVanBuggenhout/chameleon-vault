import { BigQuery } from '@google-cloud/bigquery';
import { parseBigQueryResourceId } from '../gcp/bigquery-schema-service.js';
import { PiiRegistryService } from './pii-registry-service.js';
import type { PiiRegistryEntry } from '../types/pii-registry.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('source-redaction-service');

// Real BigQuery column/table identifiers only -- never taken from anything
// outside a stored PiiRegistryEntry, but validated anyway before use in a
// generated SQL string. BigQuery has no way to parameterize an identifier
// (only values), so this is the only guard between a malformed/malicious
// declaration and a broken or dangerous UPDATE statement -- the same class
// of bug already hit twice this week (unquoted hyphenated identifiers in
// decrypted-view-service.ts) is genuinely worse here, since this runs a
// real write against a customer's own table, not just a SELECT.
const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

export interface SourceRedactionResult {
  resourceId: string;
  success: boolean;
  rowsAffected?: number;
  error?: string;
}

/**
 * Executes the REDACT_IN_PLACE source-redaction strategy: for every
 * manually-declared resource a tenant has opted into it for, nulls out
 * exactly the declared PII columns for one user's rows in that resource's
 * own source table -- never deletes rows, never touches any other column.
 *
 * Deliberately separate from JanitorService/ConnectorRegistry: those model
 * a fixed set of globally-registered SaaS destinations (one connector
 * instance per system, e.g. "hubspot"), not an open-ended, per-declaration
 * set of customer-owned BigQuery tables each with their own table name and
 * column names taken from the registry entry itself.
 */
export class SourceRedactionService {
  constructor(
    private readonly registryService: PiiRegistryService,
    private readonly bq: BigQuery
  ) {}

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
      .filter((entry) => entry.sourceRedactionStrategy === 'REDACT_IN_PLACE');
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

    const identifiersToValidate = [resource.userIdColumn, resource.tenantIdColumn, ...fieldsToRedact].filter(
      (v): v is string => v !== undefined
    );
    for (const identifier of identifiersToValidate) {
      if (!SAFE_IDENTIFIER.test(identifier)) {
        throw new Error(`Refusing to redact: "${identifier}" is not a safe column identifier.`);
      }
    }

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
}

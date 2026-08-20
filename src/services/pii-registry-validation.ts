import {
  MANUAL_OWNER_CONNECTOR,
  type DeletionStrategy,
  type GhostDataScanPolicy,
  type PiiClassification,
  type PiiFieldPolicy,
  type PiiHandling,
  type PiiRegistryDeclarationInput,
  type PiiRegistryEntry,
  type PiiResourceLayer,
  type PiiResourceVisibility,
  type PiiSystem,
  type RegistryEntryStatus,
  type SourceRedactionStrategy,
} from '../types/pii-registry.js';
import { resolveSourceRedactionStrategies } from './source-redaction-strategies.js';

const SYSTEMS: PiiSystem[] = ['bigquery', 'gcs', 'firestore', 'log', 'hubspot', 'salesforce', 'external'];
const CLASSIFICATIONS: PiiClassification[] = [
  'DIRECT_IDENTIFIER',
  'QUASI_IDENTIFIER',
  'CONTACT',
  'SENSITIVE',
  'BEHAVIORAL',
  'SYSTEM_IDENTIFIER',
];
const HANDLINGS: PiiHandling[] = ['ENCRYPT', 'TOKENIZE', 'REDACT', 'HASH_SURROGATE', 'ALLOW_AGGREGATE_ONLY', 'MANUAL_REVIEW'];
const DELETION_STRATEGIES: DeletionStrategy[] = ['CRYPTO_SHRED', 'DELETE_ROWS', 'REDACT_FIELDS', 'EXTERNAL_WIPE', 'MANUAL_REVIEW'];
const SOURCE_REDACTION_STRATEGIES: SourceRedactionStrategy[] = ['NONE', 'REDACT_IN_PLACE', 'SHADOW_COPY', 'ENCRYPTED_COPY'];
// The array field's members -- deliberately excludes 'NONE', which is only
// ever the legacy singular field's "nothing" value (an empty array is the
// array field's equivalent).
const SOURCE_REDACTION_ARRAY_STRATEGIES: SourceRedactionStrategy[] = ['REDACT_IN_PLACE', 'SHADOW_COPY', 'ENCRYPTED_COPY'];
const LAYERS: PiiResourceLayer[] = ['RAW', 'STAGING', 'INTERMEDIATE', 'MART', 'SAAS'];
const VISIBILITIES: PiiResourceVisibility[] = ['CUSTOMER_FACING', 'INTERNAL'];
const STATUSES: RegistryEntryStatus[] = ['APPROVED', 'PENDING_REVIEW', 'DEPRECATED', 'DISABLED'];
const SCAN_MODES: GhostDataScanPolicy['scanMode'][] = ['FULL', 'SAMPLED', 'DISABLED'];

export interface ValidationResult {
  entry?: PiiRegistryEntry;
  errors: string[];
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Validates a user-supplied declaration and, if valid, assembles the canonical
 * PiiRegistryEntry (ownerConnector='manual', server-managed timestamps/version).
 * Returns collected human-readable errors instead of throwing so the API and the
 * Console can surface every problem at once.
 */
export function buildManualEntry(
  input: PiiRegistryDeclarationInput,
  tenantId: string,
  now: Date = new Date(),
  existing?: PiiRegistryEntry,
  /** The resolved analyst/console-session identity that made this call, if any -- see PiiRegistryEntry.declaredBy. */
  actorEmail?: string
): ValidationResult {
  const errors: string[] = [];

  if (!isNonEmptyString(tenantId)) {
    errors.push('tenantId is required (pass it via the x-tenant-id header).');
  }

  if (!isNonEmptyString(input.resourceId)) {
    errors.push('resourceId is required.');
  } else if (!/^[a-z]+:[^\s]+$/.test(input.resourceId)) {
    errors.push('resourceId must be a URI-like value such as "bigquery:project.dataset.table" or "gcs:bucket/prefix".');
  }

  if (!SYSTEMS.includes(input.system)) {
    errors.push(`system must be one of: ${SYSTEMS.join(', ')}.`);
  }

  if (input.resourceLayer !== undefined && !LAYERS.includes(input.resourceLayer)) {
    errors.push(`resourceLayer must be one of: ${LAYERS.join(', ')}.`);
  }
  if (input.visibility !== undefined && !VISIBILITIES.includes(input.visibility)) {
    errors.push(`visibility must be one of: ${VISIBILITIES.join(', ')}.`);
  }
  if (input.deletionStrategy !== undefined && !DELETION_STRATEGIES.includes(input.deletionStrategy)) {
    errors.push(`deletionStrategy must be one of: ${DELETION_STRATEGIES.join(', ')}.`);
  }
  if (
    input.sourceRedactionStrategy !== undefined &&
    !SOURCE_REDACTION_STRATEGIES.includes(input.sourceRedactionStrategy)
  ) {
    errors.push(`sourceRedactionStrategy must be one of: ${SOURCE_REDACTION_STRATEGIES.join(', ')}.`);
  }
  if (input.sourceRedactionStrategies !== undefined) {
    if (!Array.isArray(input.sourceRedactionStrategies)) {
      errors.push('sourceRedactionStrategies must be an array.');
    } else {
      input.sourceRedactionStrategies.forEach((strategy, index) => {
        if (!SOURCE_REDACTION_ARRAY_STRATEGIES.includes(strategy)) {
          errors.push(
            `sourceRedactionStrategies[${index}] must be one of: ${SOURCE_REDACTION_ARRAY_STRATEGIES.join(', ')} ('NONE' is not valid inside the array -- send an empty array for none).`
          );
        }
      });
    }
  }
  // REDACT_IN_PLACE generates a real UPDATE against the customer's own table,
  // SHADOW_COPY and ENCRYPTED_COPY both key their table/view off the same
  // column -- all three need a real userIdColumn, and this is real
  // destructive/stateful functionality, not just descriptive metadata like
  // the rest of this schema. Fail closed rather than silently accepting a
  // declaration that could later redact or copy an entire table keyed on
  // nothing. Checks the resolved set (array if present, else the legacy
  // singular field) so this applies uniformly regardless of which the
  // caller sent.
  const requestedSourceRedactionStrategies = resolveSourceRedactionStrategies({
    sourceRedactionStrategy: input.sourceRedactionStrategy,
    sourceRedactionStrategies: input.sourceRedactionStrategies,
  });
  if (requestedSourceRedactionStrategies.length > 0 && !isNonEmptyString(input.userIdColumn)) {
    errors.push('userIdColumn is required when sourceRedactionStrategies is non-empty (REDACT_IN_PLACE, SHADOW_COPY, and ENCRYPTED_COPY all need it).');
  }
  // A real, twice-confirmed mistake (agencyAndOfficeMigration, then
  // federated_user): declaring the same column as both userIdColumn and
  // tenantIdColumn. For REDACT_IN_PLACE this produces a WHERE clause
  // (col = @userId AND col = @tenantId) that can never match any row --
  // silent no-op redaction, later certified as ERASED regardless. For
  // pii_vault sync (pii_vault_sync.py's _sync_chunk) it's worse and
  // doesn't require REDACT_IN_PLACE to trigger: every synced row's
  // tenant_id becomes a per-user value instead of the real tenant, making
  // every tenant-scoped read (decrypt-on-demand, decrypted views) come up
  // empty for data that's genuinely there. Reject outright rather than
  // warn -- there's no legitimate reason for these to be the same column.
  if (
    isNonEmptyString(input.userIdColumn) &&
    isNonEmptyString(input.tenantIdColumn) &&
    input.userIdColumn === input.tenantIdColumn
  ) {
    errors.push('userIdColumn and tenantIdColumn cannot be the same column -- this makes every row\'s tenant_id a per-user value instead of a real tenant identifier, and (with REDACT_IN_PLACE/SHADOW_COPY) an unsatisfiable WHERE clause. Leave tenantIdColumn unset for a single-tenant source.');
  }
  if (input.status !== undefined && !STATUSES.includes(input.status)) {
    errors.push(`status must be one of: ${STATUSES.join(', ')}.`);
  }

  if (!Array.isArray(input.piiFields) || input.piiFields.length === 0) {
    errors.push('piiFields must contain at least one field.');
  } else {
    input.piiFields.forEach((field, index) => {
      if (!isNonEmptyString(field.name)) {
        errors.push(`piiFields[${index}].name is required.`);
      }
      if (!CLASSIFICATIONS.includes(field.classification)) {
        errors.push(`piiFields[${index}].classification must be one of: ${CLASSIFICATIONS.join(', ')}.`);
      }
      if (!HANDLINGS.includes(field.handling)) {
        errors.push(`piiFields[${index}].handling must be one of: ${HANDLINGS.join(', ')}.`);
      }
    });
  }

  if (input.ghostDataScan?.scanMode !== undefined && !SCAN_MODES.includes(input.ghostDataScan.scanMode)) {
    errors.push(`ghostDataScan.scanMode must be one of: ${SCAN_MODES.join(', ')}.`);
  }

  if (errors.length > 0) {
    return { errors };
  }

  const piiFields: PiiFieldPolicy[] = input.piiFields.map((field) => ({
    name: field.name,
    classification: field.classification,
    handling: field.handling,
    requiredInMart: Boolean(field.requiredInMart),
    confidence: 'DECLARED',
    evidence: ['console:manual-declaration'],
  }));

  const ghostDataScan: GhostDataScanPolicy = {
    enabled: input.ghostDataScan?.enabled ?? true,
    scanMode: input.ghostDataScan?.scanMode ?? 'SAMPLED',
    patterns: input.ghostDataScan?.patterns ?? ['EMAIL', 'PHONE', 'NAME'],
  };

  const nowIso = now.toISOString();
  const entry: PiiRegistryEntry = {
    registryVersion: nowIso.slice(0, 10),
    resourceId: input.resourceId,
    system: input.system,
    resourceLayer: input.resourceLayer,
    visibility: input.visibility ?? 'CUSTOMER_FACING',
    tenantIdColumn: input.tenantIdColumn,
    userIdColumn: input.userIdColumn,
    updatedAtColumn: input.updatedAtColumn,
    piiFields,
    ownerConnector: MANUAL_OWNER_CONNECTOR,
    lineageDestination: input.resourceId,
    deletionStrategy: input.deletionStrategy ?? 'CRYPTO_SHRED',
    // Legacy singular field kept for read-compat with pre-array documents
    // (see its @deprecated doc comment) -- never read back directly by new
    // code, but still written so anything not yet migrated to
    // resolveSourceRedactionStrategies() keeps working.
    sourceRedactionStrategy: input.sourceRedactionStrategy ?? 'NONE',
    sourceRedactionStrategies: requestedSourceRedactionStrategies,
    ghostDataScan,
    handlingPolicy: 'manual_declaration',
    evidencePointers: ['console:manual-declaration'],
    notes: input.notes,
    tenantId,
    status: input.status ?? 'PENDING_REVIEW',
    createdAt: existing?.createdAt ?? nowIso,
    updatedAt: nowIso,
    declaredBy: existing?.declaredBy ?? actorEmail,
    // Reflects who made *this* write, honestly -- left unset (not carried
    // forward from a previous update) when this call has no resolvable
    // individual identity, e.g. the shared write token, rather than
    // misattributing this change to whoever last had a real credential.
    lastModifiedBy: actorEmail,
  };

  return { entry, errors: [] };
}

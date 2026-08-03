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
const SOURCE_REDACTION_STRATEGIES: SourceRedactionStrategy[] = ['NONE', 'REDACT_IN_PLACE', 'SHADOW_COPY'];
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
  existing?: PiiRegistryEntry
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
  // REDACT_IN_PLACE generates a real UPDATE against the customer's own table,
  // scoped by userIdColumn -- without one there is no safe WHERE clause, and
  // this is real destructive-write functionality, not just descriptive
  // metadata like the rest of this schema. Fail closed rather than silently
  // accepting a declaration that could later redact an entire table.
  if (
    (input.sourceRedactionStrategy === 'REDACT_IN_PLACE' || input.sourceRedactionStrategy === 'SHADOW_COPY') &&
    !isNonEmptyString(input.userIdColumn)
  ) {
    errors.push('userIdColumn is required when sourceRedactionStrategy is REDACT_IN_PLACE or SHADOW_COPY.');
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
    piiFields,
    ownerConnector: MANUAL_OWNER_CONNECTOR,
    lineageDestination: input.resourceId,
    deletionStrategy: input.deletionStrategy ?? 'CRYPTO_SHRED',
    sourceRedactionStrategy: input.sourceRedactionStrategy ?? 'NONE',
    ghostDataScan,
    handlingPolicy: 'manual_declaration',
    evidencePointers: ['console:manual-declaration'],
    notes: input.notes,
    tenantId,
    status: input.status ?? 'PENDING_REVIEW',
    createdAt: existing?.createdAt ?? nowIso,
    updatedAt: nowIso,
  };

  return { entry, errors: [] };
}

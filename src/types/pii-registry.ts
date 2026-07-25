export type PiiSystem =
  | 'bigquery'
  | 'snowflake'
  | 'gcs'
  | 'firestore'
  | 'log'
  | 'hubspot'
  | 'salesforce'
  | 'external';

export type PiiClassification =
  | 'DIRECT_IDENTIFIER'
  | 'QUASI_IDENTIFIER'
  | 'CONTACT'
  | 'SENSITIVE'
  | 'BEHAVIORAL'
  | 'SYSTEM_IDENTIFIER';

export type PiiHandling =
  | 'ENCRYPT'
  | 'TOKENIZE'
  | 'REDACT'
  | 'HASH_SURROGATE'
  | 'ALLOW_AGGREGATE_ONLY'
  | 'MANUAL_REVIEW';

export type DeletionStrategy =
  | 'CRYPTO_SHRED'
  | 'DELETE_ROWS'
  | 'REDACT_FIELDS'
  | 'EXTERNAL_WIPE'
  | 'MANUAL_REVIEW';

export type RegistryConfidence = 'DECLARED' | 'INFERRED_HIGH' | 'INFERRED_MEDIUM' | 'INFERRED_LOW';

export type PiiResourceLayer = 'RAW' | 'STAGING' | 'INTERMEDIATE' | 'MART' | 'SAAS';

export type PiiResourceVisibility = 'CUSTOMER_FACING' | 'INTERNAL';

export type RegistryEntryStatus = 'APPROVED' | 'PENDING_REVIEW' | 'DEPRECATED' | 'DISABLED';

export interface PiiFieldPolicy {
  name: string;
  classification: PiiClassification;
  handling: PiiHandling;
  requiredInMart: boolean;
  evidence?: string[];
  confidence?: RegistryConfidence;
  surrogateId?: string;
}

export interface GhostDataScanPolicy {
  enabled: boolean;
  scanMode: 'FULL' | 'SAMPLED' | 'DISABLED';
  patterns: string[];
}

export interface PiiRegistryEntry {
  registryVersion: string;
  resourceId: string;
  system: PiiSystem;
  resourceLayer?: PiiResourceLayer;
  visibility?: PiiResourceVisibility;
  tenantIdColumn?: string;
  userIdColumn?: string;
  piiFields: PiiFieldPolicy[];
  ownerConnector: string;
  lineageDestination: string;
  deletionStrategy: DeletionStrategy;
  ghostDataScan: GhostDataScanPolicy;
  handlingPolicy: string;
  evidencePointers: string[];
  notes?: string;
  /**
   * Owning tenant. `undefined` denotes a platform/global entry (the bundled connector
   * seed and the dbt slice) that is visible to every tenant. User-declared ("manual")
   * entries always carry a concrete tenantId and are only visible to that tenant.
   */
  tenantId?: string;
  status?: RegistryEntryStatus;
  createdAt?: string;
  updatedAt?: string;
}

/** A single PII field as supplied by a user declaring a resource. */
export interface PiiFieldDeclarationInput {
  name: string;
  classification: PiiClassification;
  handling: PiiHandling;
  requiredInMart?: boolean;
}

/**
 * The payload a Chameleon user submits to declare (or update) a PII resource — e.g. a
 * Fivetran-created BigQuery table. Server-managed fields (ownerConnector, registryVersion,
 * timestamps, evidence) are filled in by the Key Vault, not the caller.
 */
export interface PiiRegistryDeclarationInput {
  resourceId: string;
  system: PiiSystem;
  resourceLayer?: PiiResourceLayer;
  visibility?: PiiResourceVisibility;
  tenantIdColumn?: string;
  userIdColumn?: string;
  piiFields: PiiFieldDeclarationInput[];
  deletionStrategy?: DeletionStrategy;
  ghostDataScan?: Partial<GhostDataScanPolicy>;
  status?: RegistryEntryStatus;
  notes?: string;
}

/** Marks entries created through the user-facing declare API. */
export const MANUAL_OWNER_CONNECTOR = 'manual';

export interface RegistryPolicyIssue {
  code:
    | 'MISSING_TENANT_SCOPE'
    | 'MISSING_USER_SCOPE'
    | 'DIRECT_IDENTIFIER_IN_MART'
    | 'MANUAL_REVIEW_REQUIRED'
    | 'GHOST_SCAN_DISABLED';
  severity: 'INFO' | 'WARNING' | 'ERROR';
  resourceId: string;
  field?: string;
  message: string;
}

export interface RegistryPolicyEvaluation {
  resourceId: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  issues: RegistryPolicyIssue[];
}

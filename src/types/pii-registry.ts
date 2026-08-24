export type PiiSystem =
  | 'bigquery'
  | 'snowflake'
  | 'gcs'
  | 'firestore'
  | 'log'
  | 'hubspot'
  | 'salesforce'
  | 'external'
  | 'pubsub';

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

/**
 * What (if anything) happens to a manually-declared resource's own source
 * table when a user is deleted -- distinct from deletionStrategy, which
 * governs Chameleon's own copy (pii_vault). A manually-declared resource is,
 * by definition, a table the customer already owned before Chameleon ever
 * touched it (see chameleon-data-pipelines' pii_vault_sync.py); crypto-
 * shredding the key only ever cuts off Chameleon's encrypted copy and
 * anything decrypted from it, never the original plaintext sitting in that
 * source table. This field is how the person declaring the resource
 * explicitly opts in to (or out of) Chameleon also acting on that source --
 * never assumed, always chosen.
 *
 * - NONE (default): leave the source table exactly as-is. Zero write access
 *   needed, zero risk of regressing anyone who doesn't opt in.
 * - REDACT_IN_PLACE: on that user's deletion, null out the declared PII
 *   columns directly in the source table (never delete rows, never touch
 *   other columns). Requires a real, narrow write grant on that table.
 * - SHADOW_COPY: never touch the source table; instead expose a separate
 *   de-identified copy/view alongside it that mirrors the source but drops
 *   a user's PII once their key is shredded.
 * - ENCRYPTED_COPY: never touch the source table; instead maintain a
 *   physical `{table}_encrypted` view (backed by an append-only
 *   `{table}_encrypted_raw` table) mirroring the source but with declared
 *   PII columns holding ciphertext instead of plaintext -- for downstream
 *   consumers (e.g. dbt) that need a stable table shape without ever
 *   touching raw PII. On deletion, the user's row is actually removed from
 *   the raw table (unlike SHADOW_COPY's view, which just stops decrypting).
 *
 * Only ever meaningful for manually-declared (ownerConnector === 'manual')
 * resources -- automated-ingestion resources store only ciphertext at the
 * source already, so there's nothing to redact there.
 *
 * REDACT_IN_PLACE, SHADOW_COPY, and ENCRYPTED_COPY are independently
 * combinable on the same resource (see sourceRedactionStrategies below) --
 * NONE is only ever the single-value legacy field's default, never a
 * member of the array.
 */
export type SourceRedactionStrategy = 'NONE' | 'REDACT_IN_PLACE' | 'SHADOW_COPY' | 'ENCRYPTED_COPY';

export type RegistryConfidence = 'DECLARED' | 'INFERRED_HIGH' | 'INFERRED_MEDIUM' | 'INFERRED_LOW';

export type PiiResourceLayer = 'RAW' | 'STAGING' | 'INTERMEDIATE' | 'MART' | 'SAAS';

export type PiiResourceVisibility = 'CUSTOMER_FACING' | 'INTERNAL';

export type RegistryEntryStatus = 'APPROVED' | 'PENDING_REVIEW' | 'DEPRECATED' | 'DISABLED';

export interface PiiFieldPolicy {
  /**
   * A real BigQuery column name for every other system. For
   * `system: 'pubsub'`, this is instead a dotted JSON path into each
   * message's decoded body (e.g. "after.email") -- reused rather than
   * given a parallel field-list shape, since every other declared-field
   * concept (classification, handling, requiredInMart) applies identically
   * either way.
   */
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
  /**
   * Only meaningful for `system: 'pubsub'`. The numeric unique ID (JWT `sub`
   * claim, never the email -- a real Google-signed push-subscription token
   * carries no `email` claim, confirmed the hard way against BigQuery's own
   * connection SA in decrypted-views-decrypt.ts) of the service account the
   * customer's own push subscription authenticates as. Compared against
   * every incoming push's verified ID token before anything in the message
   * is trusted -- this is the entire authorization boundary for the
   * pubsub-ingest endpoint, which is otherwise publicly reachable (see that
   * service's own docs for why it can't be gated by Cloud Run IAM invoker
   * the way an internal, statically-known caller can be).
   */
  pubsubAllowedCallerServiceAccount?: string;
  /**
   * Only meaningful for `system: 'pubsub'`. Dotted JSON path to the user-id
   * field within each message's decoded body (e.g. "after.user_id" for a
   * Debezium-style change event) -- the pubsub equivalent of userIdColumn.
   * No nested-schema introspection for v1 (there's no reliable schema to
   * introspect without Pub/Sub's optional, not-always-attached native
   * Schema resource) -- plain dotted-path text entry only.
   */
  userIdFieldPath?: string;
  /**
   * Which source-table column tracks last-modified, if the customer has
   * declared one -- lets chameleon-data-pipelines' daily pii_vault sync scan
   * only rows changed since lastSyncedAt instead of the whole table every
   * day. Opt-in: only 'manual' resources with both this AND lastSyncedAt set
   * get incremental treatment (see pii_vault_sync.py); absent, the resource
   * keeps the original full-scan behavior unchanged.
   */
  updatedAtColumn?: string;
  /**
   * Server-managed watermark (ISO8601), advanced only via
   * POST /pii-registry/resources/:resourceId/mark-synced -- never set
   * directly through the declare/update API. Cleared (not left stale)
   * whenever updatedAtColumn is cleared, so a resource can't be stuck
   * thinking it's incremental-eligible after a customer turns it off.
   */
  lastSyncedAt?: string;
  /**
   * Server-managed (ISO8601), advanced via
   * POST /pii-registry/resources/:resourceId/mark-sync-attempted after
   * *every* successful sync run for this resource -- full scan or
   * incremental, regardless of whether updatedAtColumn is set. Distinct
   * from lastSyncedAt on purpose: lastSyncedAt is specifically the
   * incremental watermark, which stays unset for a resource with no
   * updatedAtColumn even though real full syncs have genuinely completed
   * for it (a resource "never synced" and one that's synced many times via
   * full scans looked identical from the registry UI before this existed).
   * Console displays this for "last synced," not lastSyncedAt.
   */
  lastSyncAttemptAt?: string;
  piiFields: PiiFieldPolicy[];
  ownerConnector: string;
  lineageDestination: string;
  deletionStrategy: DeletionStrategy;
  /**
   * @deprecated Superseded by sourceRedactionStrategies (a resource can now
   * combine more than one strategy). Kept, never written by new
   * declares/updates, so existing Firestore documents that predate the
   * array field keep working -- read via resolveSourceRedactionStrategies()
   * (source-redaction-strategies.ts), never this field directly.
   */
  sourceRedactionStrategy?: SourceRedactionStrategy;
  /**
   * Zero or more of REDACT_IN_PLACE / SHADOW_COPY / ENCRYPTED_COPY,
   * independently combinable ('NONE' is never a member -- an empty array
   * means no source redaction). Absent on any entry declared before this
   * field existed; always resolve via resolveSourceRedactionStrategies(),
   * never read this directly, so old and new entries behave identically.
   */
  sourceRedactionStrategies?: SourceRedactionStrategy[];
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
  /**
   * Email of whoever first declared this resource, set once and never
   * overwritten by later updates. Only populated when the request that
   * created it carried a real, resolvable per-analyst or console-session
   * credential (see middleware/auth.ts) -- absent for entries declared with
   * the shared write token (no individual to attribute) or platform-seeded
   * connector entries, never a guessed or invented identity.
   */
  declaredBy?: string;
  /** Email of whoever most recently declared/updated this resource. Same attribution caveat as declaredBy. */
  lastModifiedBy?: string;
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
  /** See PiiRegistryEntry.pubsubAllowedCallerServiceAccount. Only meaningful for system: 'pubsub'. */
  pubsubAllowedCallerServiceAccount?: string;
  /** See PiiRegistryEntry.userIdFieldPath. Only meaningful for system: 'pubsub'. */
  userIdFieldPath?: string;
  /** See PiiRegistryEntry.updatedAtColumn. Omit or send an empty string to clear it. */
  updatedAtColumn?: string;
  piiFields: PiiFieldDeclarationInput[];
  deletionStrategy?: DeletionStrategy;
  /** @deprecated Send sourceRedactionStrategies instead. Only meaningful for manually-declared resources. */
  sourceRedactionStrategy?: SourceRedactionStrategy;
  /** Only meaningful for manually-declared resources. Zero or more of REDACT_IN_PLACE/SHADOW_COPY/ENCRYPTED_COPY; omit or send [] for none. */
  sourceRedactionStrategies?: SourceRedactionStrategy[];
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

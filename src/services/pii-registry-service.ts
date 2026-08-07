import {
  MANUAL_OWNER_CONNECTOR,
  type PiiFieldPolicy,
  type PiiRegistryEntry,
  type RegistryPolicyEvaluation,
  type RegistryPolicyIssue,
} from '../types/pii-registry.js';

/**
 * Persistence port for user-declared ("manual") registry entries. The in-memory
 * service stays authoritative for the hot read path; implementations persist the
 * durable copy (Firestore) and any audit mirror (BigQuery). Injected so the service
 * is unit-testable with a fake.
 */
export interface PiiDeclarationStore {
  upsert(entry: PiiRegistryEntry): Promise<void>;
  delete(tenantId: string, resourceId: string): Promise<void>;
  advanceSyncWatermark(tenantId: string, resourceId: string, candidateIso: string): Promise<string | undefined>;
}

const GLOBAL_SCOPE = '*';

export class PiiRegistryService {
  private readonly entries: Map<string, PiiRegistryEntry>;

  constructor(
    entries: PiiRegistryEntry[],
    private readonly store?: PiiDeclarationStore
  ) {
    this.entries = new Map(entries.map((entry) => [PiiRegistryService.keyOf(entry.tenantId, entry.resourceId), entry]));
  }

  private static keyOf(tenantId: string | undefined, resourceId: string): string {
    return `${tenantId ?? GLOBAL_SCOPE}::${resourceId}`;
  }

  /** An entry is visible to a tenant if it is global (no tenantId) or owned by that tenant. */
  private static visibleTo(entry: PiiRegistryEntry, tenantId?: string): boolean {
    if (tenantId === undefined) {
      return true; // no tenant filter requested
    }
    return entry.tenantId === undefined || entry.tenantId === tenantId;
  }

  listEntries(
    filters: { tenantId?: string; system?: string; ownerConnector?: string; scanEnabled?: boolean } = {}
  ): PiiRegistryEntry[] {
    return this.getEntries()
      .filter((entry) => PiiRegistryService.visibleTo(entry, filters.tenantId))
      .filter((entry) => !filters.system || entry.system === filters.system)
      .filter((entry) => !filters.ownerConnector || entry.ownerConnector === filters.ownerConnector)
      .filter((entry) => filters.scanEnabled === undefined || entry.ghostDataScan.enabled === filters.scanEnabled);
  }

  getEntry(resourceId: string, tenantId?: string): PiiRegistryEntry | undefined {
    if (tenantId !== undefined) {
      // Prefer a tenant-owned entry, then fall back to a global one with the same id.
      return (
        this.entries.get(PiiRegistryService.keyOf(tenantId, resourceId)) ??
        this.entries.get(PiiRegistryService.keyOf(undefined, resourceId))
      );
    }
    // No tenant context: prefer the global entry, else any entry with this resourceId.
    return (
      this.entries.get(PiiRegistryService.keyOf(undefined, resourceId)) ??
      this.getEntries().find((entry) => entry.resourceId === resourceId)
    );
  }

  findByLineageDestination(destination: string): PiiRegistryEntry[] {
    return this.getEntries().filter((entry) => entry.lineageDestination === destination || entry.resourceId === destination);
  }

  /**
   * Creates or replaces a user-declared entry. Only manual, tenant-scoped entries are
   * mutable — the bundled connector seed and the dbt slice are read-only. Persists
   * through the store (if configured) before updating the in-memory copy, so a failed
   * write never leaves the hot path ahead of durable state.
   */
  async upsertEntry(entry: PiiRegistryEntry): Promise<PiiRegistryEntry> {
    if (entry.ownerConnector !== MANUAL_OWNER_CONNECTOR) {
      throw new RegistryMutationError('Only manually declared entries can be written.', 'IMMUTABLE_OWNER');
    }
    if (!entry.tenantId) {
      throw new RegistryMutationError('A manual entry must carry a tenantId.', 'MISSING_TENANT');
    }
    await this.store?.upsert(entry);
    this.entries.set(PiiRegistryService.keyOf(entry.tenantId, entry.resourceId), entry);
    return entry;
  }

  /** Removes a tenant-owned manual entry. Refuses to touch global/dbt/connector entries. */
  async removeEntry(resourceId: string, tenantId: string): Promise<boolean> {
    const key = PiiRegistryService.keyOf(tenantId, resourceId);
    const existing = this.entries.get(key);
    if (!existing) {
      return false;
    }
    if (existing.ownerConnector !== MANUAL_OWNER_CONNECTOR) {
      throw new RegistryMutationError('Only manually declared entries can be removed.', 'IMMUTABLE_OWNER');
    }
    await this.store?.delete(tenantId, resourceId);
    this.entries.delete(key);
    return true;
  }

  /**
   * Advances a resource's sync watermark after chameleon-data-pipelines'
   * daily/on-demand pii_vault sync successfully covers it. Persists through
   * the store's compare-and-swap (see FirestorePiiDeclarationRepository.
   * advanceSyncWatermark) first, then updates the in-memory hot-path copy to
   * whatever the store says actually landed -- not blindly to candidateIso,
   * since a concurrent, later-finishing run may have already advanced it
   * further.
   */
  async markResourceSynced(
    resourceId: string,
    tenantId: string,
    candidateIso: string
  ): Promise<PiiRegistryEntry | undefined> {
    const key = PiiRegistryService.keyOf(tenantId, resourceId);
    const existing = this.entries.get(key);
    if (!existing) {
      return undefined;
    }
    if (existing.ownerConnector !== MANUAL_OWNER_CONNECTOR) {
      throw new RegistryMutationError('Only manually declared entries can be marked synced.', 'IMMUTABLE_OWNER');
    }
    const stored = (await this.store?.advanceSyncWatermark(tenantId, resourceId, candidateIso)) ?? candidateIso;
    const updated: PiiRegistryEntry = { ...existing, lastSyncedAt: stored };
    this.entries.set(key, updated);
    return updated;
  }

  evaluateAll(tenantId?: string): RegistryPolicyEvaluation[] {
    return this.listEntries({ tenantId }).map((entry) => this.evaluateEntry(entry));
  }

  evaluateEntry(entry: PiiRegistryEntry): RegistryPolicyEvaluation {
    const issues: RegistryPolicyIssue[] = [];
    const resourceName = entry.resourceId.split(':').pop() || entry.resourceId;
    const isWarehouseResource = entry.system === 'bigquery';
    const isMart = resourceName.includes('.mart_') || resourceName.startsWith('mart_');

    if (isWarehouseResource && !entry.tenantIdColumn) {
      issues.push({
        code: 'MISSING_TENANT_SCOPE',
        severity: 'ERROR',
        resourceId: entry.resourceId,
        message: 'Tenant-scoped warehouse resources must declare tenantIdColumn.',
      });
    }

    if (entry.deletionStrategy === 'CRYPTO_SHRED' && !entry.userIdColumn) {
      issues.push({
        code: 'MISSING_USER_SCOPE',
        severity: 'ERROR',
        resourceId: entry.resourceId,
        message: 'Crypto-shredded resources must declare how user scope is represented.',
      });
    }

    if (entry.deletionStrategy === 'MANUAL_REVIEW') {
      issues.push({
        code: 'MANUAL_REVIEW_REQUIRED',
        severity: 'WARNING',
        resourceId: entry.resourceId,
        message: 'Manual review is required before this resource can be considered fully automated.',
      });
    }

    for (const field of entry.piiFields) {
      this.evaluateField(entry, field, isMart, issues);
    }

    if (!entry.ghostDataScan.enabled) {
      issues.push({
        code: 'GHOST_SCAN_DISABLED',
        severity: 'INFO',
        resourceId: entry.resourceId,
        message: 'Ghost-data scanning is disabled for this resource.',
      });
    }

    return {
      resourceId: entry.resourceId,
      status: issues.some((issue) => issue.severity === 'ERROR')
        ? 'FAIL'
        : issues.some((issue) => issue.severity === 'WARNING')
          ? 'WARN'
          : 'PASS',
      issues,
    };
  }

  private evaluateField(
    entry: PiiRegistryEntry,
    field: PiiFieldPolicy,
    isMart: boolean,
    issues: RegistryPolicyIssue[]
  ): void {
    if (isMart && field.classification === 'DIRECT_IDENTIFIER' && field.handling !== 'ALLOW_AGGREGATE_ONLY') {
      issues.push({
        code: 'DIRECT_IDENTIFIER_IN_MART',
        severity: 'ERROR',
        resourceId: entry.resourceId,
        field: field.name,
        message: 'Mart resources may not expose direct identifiers without aggregate-only approval.',
      });
    }

    if (field.handling === 'MANUAL_REVIEW') {
      issues.push({
        code: 'MANUAL_REVIEW_REQUIRED',
        severity: 'WARNING',
        resourceId: entry.resourceId,
        field: field.name,
        message: 'Manual review is required before this resource can be considered fully automated.',
      });
    }
  }

  private getEntries(): PiiRegistryEntry[] {
    return [...this.entries.values()];
  }
}

export type RegistryMutationErrorCode = 'IMMUTABLE_OWNER' | 'MISSING_TENANT';

export class RegistryMutationError extends Error {
  constructor(
    message: string,
    public readonly code: RegistryMutationErrorCode
  ) {
    super(message);
    this.name = 'RegistryMutationError';
  }
}

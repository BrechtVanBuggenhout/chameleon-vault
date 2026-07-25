export interface LineageDestination {
  name: string;
  lastSeen: Date;
}

export interface LineageEvent {
  eventId: string;
  userId: string;
  tenantId?: string;
  user_id?: string; // snake_case alias
  operationId?: string;
  operation_id?: string; // snake_case alias
  source: string;
  destination: string;
  eventType?: string;
  event_type?: string; // snake_case alias
  deletionRequestId?: string;
  deletion_request_id?: string; // snake_case alias
  context?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  timestamp: Date;
  // Ghost data classification (Phase 5.4)
  dataClassification?: 'PII' | 'ENCRYPTED_ONLY' | 'UNSTRUCTURED_CACHE' | 'GHOST_DATA' | 'AUDIT_TRAIL' | 'METADATA' | 'UNKNOWN';
  data_classification?: string; // snake_case alias
  retentionPolicy?: 'DELETE' | 'REDACT' | 'IMMUTABLE';
  retention_policy?: string; // snake_case alias
}

export interface UserLineage {
  userId: string;
  destinations: LineageDestination[];
}

export interface GhostDataSummary {
  scope: 'USER_LINKED' | 'RESOURCE_LEVEL';
  resourceId: string;
  system: string;
  column?: string;
  pattern?: string;
  count?: number;
  confidence?: number;
  scanner?: string;
  lastSeen: string;
}

/**
 * A table the warehouse metadata crawler discovered that is NOT (fully) covered by the
 * PII registry — the raw material for the "declare this dataset" workflow in the Console.
 * Sourced from WAREHOUSE_METADATA_DISCOVERED lineage events (metadata only, never values).
 */
export interface WarehouseDiscoveryFinding {
  resourceId: string;
  system: string;
  datasetId?: string;
  tableId?: string;
  registryStatus: 'UNREGISTERED' | 'DRIFTED';
  columns: string[];
  recommendedAction?: string;
  lastSeen: string;
}

export interface DeletionPlan {
  userId: string;
  impactedDestinations: Array<{
    name: string;
    dataClassification?: string;
    action: 'DELETE' | 'WIPE_API' | 'REDACT' | 'MANUAL_REVIEW';
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  }>;
  mathematicalErasure: {
    status: 'PENDING' | 'COMPLETE';
    stores: string[];
  };
  ghostDataSummary?: GhostDataSummary[];
  timestamp: string;
}

export interface ILineageRepository {
  recordEvent(event: Omit<LineageEvent, 'eventId' | 'timestamp'>): Promise<string>;
  getUserLineage(userId: string, tenantId?: string): Promise<UserLineage>;
  getGhostDataFindings?(userId: string, tenantId?: string): Promise<GhostDataSummary[]>;
  getWarehouseDiscoveryFindings?(tenantId?: string): Promise<WarehouseDiscoveryFinding[]>;
}

export interface CertificateLineageItem {
  system: string;
  status: 'ERASED' | 'PENDING' | 'FAILED';
  // Add snake_case alias for consistency if needed, but ISO string is standard
  // timestamp_iso?: string; 
  timestamp: string;
}

export interface CertificateGhostDataItem {
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

export interface DestructionCertificateClaims {
  iss: string;           // Issuer (Chameleon Key Vault)
  sub: string;           // Subject (userId)
  tenantId?: string;     // Tenant scope for the erased identity
  tenant_id?: string;    // snake_case alias for tenantId
  iat: number;           // Issued at
  jti: string;           // Unique Certificate ID
  shredDate: string;     // ISO date of key destruction
  shred_date?: string;   // snake_case alias for shredDate
  keyFingerprint: string;// Hash of destroyed key metadata
  lineageSummary: CertificateLineageItem[];
  ghostDataSummary?: CertificateGhostDataItem[];
  ghost_data_summary?: CertificateGhostDataItem[];
  keyDestructionStatus?: string;
  warehouseData?: string;
  user_id?: string;      // snake_case alias for sub (userId)
}

export interface KeyStatus {
  status: 'ACTIVE' | 'ROTATED' | 'SHREDDED' | 'DELETED';
  created_at: string;
  createdAt?: string;
  shred_at?: string;
  shredAt?: string;
  rotated_at?: string;
  rotatedAt?: string;
  active_dek_id?: string;
  activeDekId?: string;
  encryption_version?: string;
  encryptionVersion?: string;
  destinations?: string[];
}

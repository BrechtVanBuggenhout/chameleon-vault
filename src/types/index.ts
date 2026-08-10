export interface CertificateLineageItem {
  system: string;
  // CONFIRMED_ABSENT: the destination was genuinely checked and never held
  // any PII for this user -- distinct from ERASED (real data was found and
  // removed), since a certificate that can't tell these apart can overstate
  // what actually happened.
  status: 'ERASED' | 'CONFIRMED_ABSENT' | 'PENDING' | 'FAILED';
  // Add snake_case alias for consistency if needed, but ISO string is standard
  // timestamp_iso?: string;
  timestamp: string;
}

export interface CertificateLineageCoverage {
  // Destinations the janitor actually attempted a wipe against for this
  // deletion -- not "every system this user's data ever touched" (there is
  // no source of truth for that). CASCADE_COMPLETE is only reachable once
  // every attempted destination succeeds, so checked === succeeded in
  // practice; both are stated so the claim doesn't need the reader to know
  // that invariant.
  destinationsChecked: number;
  destinationsSucceeded: number;
  // The connector types this system is capable of wiping at all -- states
  // the scope of what "checked" can mean, so the claim can't be misread as
  // exhaustive coverage of every system that might hold this user's data.
  knownDestinationTypes: string[];
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
  lineageCoverage: CertificateLineageCoverage;
  ghostDataSummary?: CertificateGhostDataItem[];
  ghost_data_summary?: CertificateGhostDataItem[];
  // Ghost-data findings above are real when present, but an empty array is
  // ambiguous on its own -- this makes explicit that no scanner in this
  // system currently records *what was scanned*, only matches it happened to
  // find, so absence of findings must not be read as "confirmed scanned, zero
  // found." 'NOT_TRACKED' until a real scan-coverage source exists.
  ghostDataScanCoverage: 'NOT_TRACKED';
  keyDestructionStatus?: string;
  // What "destroyed" actually means here: the per-user DEK ciphertext was
  // erased from Firestore (crypto-shred), a synchronous operation -- not a
  // Cloud KMS CryptoKeyVersion.destroy() call, which has a mandatory ~24h
  // scheduling window that doesn't apply to this design. Stated explicitly
  // so keyDestructionStatus: COMPLETE can't be misread as a KMS-level claim.
  keyDestructionMethod: 'DEK_ERASURE';
  warehouseData?: string;
  user_id?: string;      // snake_case alias for sub (userId)
  // Hash chain over this tenant's certificate log -- null on the very first
  // certificate a tenant ever gets, otherwise sha256 of the previous signed
  // certificate. Signed as part of the JWT (not appended after), so the
  // chain is actually tamper-evident. See CertificateChainRepository.
  previousCertificateHash: string | null;
  // null specifically means this certificate was never added to the chain
  // at all (the rare CertificateService.getCertificateForUser fallback for
  // a request stuck at CASCADE_COMPLETE with no certificate ever actually
  // issued) -- distinct from 1, the real first entry in a tenant's chain.
  chainSequence: number | null;
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

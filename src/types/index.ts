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

export interface CertificateBackupImmunityItem {
  resourceId: string;
  // 'NONE' is deliberately excluded -- a resource with no source-redaction
  // strategy declared never produces an item here at all (see
  // CertificateBackupImmunityCoverage.sourceRedactionExceptions).
  strategy: 'REDACT_IN_PLACE' | 'SHADOW_COPY' | 'ENCRYPTED_COPY';
  // Whether backups of the CUSTOMER'S OWN source table are immune to
  // recovering this user's data as of `iat` -- not a claim about Chameleon's
  // own pii_vault, which is covered unconditionally by cryptoShredCoverage
  // below regardless of what's in this array.
  backupImmune: boolean;
  // When the janitor cascade's redaction/deletion actually ran for this user.
  // Present only for REDACT_IN_PLACE/ENCRYPTED_COPY; absent for SHADOW_COPY,
  // which never runs a per-deletion step at all -- there is no "when" to
  // record, only a standing, declare-time fact.
  redactedAt?: string;
  // Present only when backupImmune is false and a future date would make it
  // true (REDACT_IN_PLACE, once BigQuery's time-travel window elapses).
  // Absent for SHADOW_COPY -- no amount of waiting makes that one true.
  immuneAsOf?: string;
  reason: string;
}

export interface CertificateBackupImmunityCoverage {
  // Always true: pii_vault and every janitor SaaS destination only ever
  // stored ciphertext, so DEK erasure makes every backup snapshot of them
  // unreadable regardless of the snapshot's age -- not conditioned on any
  // time window. Distinct from the per-resource exceptions below, which are
  // about a customer's own pre-existing source table, not Chameleon's vault.
  cryptoShredCoverage: 'BACKUP_IMMUNE';
  // Per-(resourceId, strategy) qualifications -- only for manually-declared
  // resources that opted into a source-redaction strategy. Empty when the
  // tenant has none declared, in which case cryptoShredCoverage above is the
  // complete, unconditional picture.
  sourceRedactionExceptions: CertificateBackupImmunityItem[];
  // BigQuery's platform-wide MAXIMUM time-travel window (confirmed: the
  // valid range is 48-168 hours, 168 being the ceiling, not just a common
  // default) -- restated here, like lineageCoverage.knownDestinationTypes,
  // so the claim is self-contained. Used as a conservative ceiling because
  // Chameleon cannot introspect or pin a customer's actual per-dataset
  // config on a BYOC project; 7 days is safe regardless of what that
  // customer's real setting is.
  timeTravelCeilingHours: 168;
  // BigQuery also retains an additional Google-support-assisted "fail-safe"
  // window after time-travel expires, reachable only via Google's own
  // recovery tooling, never a customer/self-service query. Stated once, here,
  // so backupImmune: true is never misread as "provably unrecoverable by
  // anyone," only as "no longer retrievable through the customer's own
  // BigQuery access."
  timeTravelCaveat: string;
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
  backupImmunity: CertificateBackupImmunityCoverage;
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

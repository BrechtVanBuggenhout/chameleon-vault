import { describe, expect, it } from '@jest/globals';
import {
  assemblePiiRegistryEntries,
  composePiiRegistry,
  type LineageRow,
  type RegistryRow,
} from '../src/gcp/pii-registry-repository.js';
import { PiiRegistryService } from '../src/services/pii-registry-service.js';
import type { PiiRegistryEntry } from '../src/types/pii-registry.js';

const stgUsersRows: RegistryRow[] = [
  {
    resource_id: 'bigquery:your-gcp-project-id.chameleon_dev.stg_users',
    model_name: 'stg_users',
    system: 'bigquery',
    resource_layer: 'STAGING',
    owner: 'dbt',
    field_name: 'email_token',
    classification: 'DIRECT_IDENTIFIER',
    handling: 'TOKENIZE',
    confidence: 'DECLARED',
    detection_method: 'DECLARED',
    required_in_mart: false,
    registry_version: '2026-06-30',
  },
  {
    resource_id: 'bigquery:your-gcp-project-id.chameleon_dev.stg_users',
    model_name: 'stg_users',
    system: 'bigquery',
    resource_layer: 'STAGING',
    owner: 'dbt',
    field_name: 'user_id',
    classification: 'SYSTEM_IDENTIFIER',
    handling: 'HASH_SURROGATE',
    confidence: 'DECLARED',
    detection_method: 'DECLARED',
    required_in_mart: false,
    registry_version: '2026-06-30',
  },
];

const rawUsersRow: RegistryRow = {
  resource_id: 'bigquery:your-gcp-project-id.chameleon_dev.raw_users',
  model_name: 'raw_users',
  system: 'bigquery',
  resource_layer: 'RAW',
  owner: 'pipelines',
  field_name: 'encrypted_pii',
  classification: 'SENSITIVE',
  handling: 'ENCRYPT',
  confidence: 'DECLARED',
  detection_method: 'DECLARED',
  required_in_mart: false,
  registry_version: '2026-06-30',
};

const lineageRows: LineageRow[] = [
  {
    source_resource_id: 'bigquery:your-gcp-project-id.chameleon_dev.stg_users',
    field_name: 'user_id',
    downstream_model: 'int_customer_activity',
    hops: 1,
  },
];

describe('assemblePiiRegistryEntries', () => {
  it('returns an empty array when there are no registry rows', () => {
    expect(assemblePiiRegistryEntries([], [])).toEqual([]);
  });

  it('groups flat field rows into one entry per resource with all PII fields', () => {
    const entries = assemblePiiRegistryEntries(stgUsersRows, lineageRows);

    expect(entries).toHaveLength(1);
    const entry = entries[0];
    expect(entry.resourceId).toBe('bigquery:your-gcp-project-id.chameleon_dev.stg_users');
    expect(entry.piiFields.map((f) => f.name)).toEqual(['email_token', 'user_id']);
    expect(entry.ownerConnector).toBe('dbt');
    expect(entry.registryVersion).toBe('2026-06-30');
  });

  it('attaches downstream lineage as evidence pointers', () => {
    const [entry] = assemblePiiRegistryEntries(stgUsersRows, lineageRows);
    expect(entry.evidencePointers).toContain('dbt:model:stg_users');
    expect(entry.evidencePointers).toContain('lineage:used_in=int_customer_activity:user_id@1hops');
  });

  it('derives RAW resources as internal with scanning disabled', () => {
    const [entry] = assemblePiiRegistryEntries([rawUsersRow], []);
    expect(entry.visibility).toBe('INTERNAL');
    expect(entry.ghostDataScan.enabled).toBe(false);
  });

  it('derives staging resources as customer-facing, crypto-shred, scan-enabled', () => {
    const [entry] = assemblePiiRegistryEntries(stgUsersRows, []);
    expect(entry.visibility).toBe('CUSTOMER_FACING');
    expect(entry.deletionStrategy).toBe('CRYPTO_SHRED');
    expect(entry.ghostDataScan.enabled).toBe(true);
  });

  it('produces entries the policy engine evaluates without ERROR-level issues (federated)', () => {
    // Downstream-safety check: derived defaults must not trip MISSING_TENANT_SCOPE
    // or MISSING_USER_SCOPE, which would mark every dbt-sourced resource as FAIL.
    const entries = assemblePiiRegistryEntries([...stgUsersRows, rawUsersRow], lineageRows);
    const service = new PiiRegistryService(entries);

    for (const evaluation of service.evaluateAll()) {
      const errors = evaluation.issues.filter((issue) => issue.severity === 'ERROR');
      expect(errors).toEqual([]);
    }
  });
});

describe('composePiiRegistry (federation by source)', () => {
  const connectorRegistry: PiiRegistryEntry[] = [
    {
      registryVersion: '2026-06-19',
      resourceId: 'hubspot:contacts',
      system: 'hubspot',
      ownerConnector: 'hubspot',
      lineageDestination: 'hubspot',
      deletionStrategy: 'EXTERNAL_WIPE',
      ghostDataScan: { enabled: false, scanMode: 'DISABLED', patterns: [] },
      handlingPolicy: 'saas_external_wipe',
      evidencePointers: [],
      piiFields: [{ name: 'email_hash', classification: 'DIRECT_IDENTIFIER', handling: 'TOKENIZE', requiredInMart: false }],
    },
    {
      registryVersion: '2026-06-21',
      resourceId: 'bigquery:chameleon_dev.stg_users',
      system: 'bigquery',
      ownerConnector: 'dbt',
      lineageDestination: 'bigquery:chameleon_dev.stg_users',
      deletionStrategy: 'CRYPTO_SHRED',
      ghostDataScan: { enabled: true, scanMode: 'SAMPLED', patterns: [] },
      handlingPolicy: 'stale_hardcoded',
      evidencePointers: [],
      piiFields: [{ name: 'old_field', classification: 'SENSITIVE', handling: 'ENCRYPT', requiredInMart: false }],
    },
  ];

  it('keeps the connector registry unchanged when the dbt slice is empty', () => {
    expect(composePiiRegistry(connectorRegistry, [])).toBe(connectorRegistry);
  });

  it('preserves non-dbt connector entries while replacing the dbt slice', () => {
    const dbtEntries = assemblePiiRegistryEntries(stgUsersRows, lineageRows);
    const composed = composePiiRegistry(connectorRegistry, dbtEntries);

    // HubSpot (connector-owned) survives.
    expect(composed.some((e) => e.resourceId === 'hubspot:contacts')).toBe(true);
    // The stale hardcoded dbt entry is gone, replaced by the fresh dbt slice.
    const stg = composed.find((e) => e.ownerConnector === 'dbt');
    expect(composed.filter((e) => e.ownerConnector === 'dbt')).toHaveLength(1);
    expect(stg?.piiFields.map((f) => f.name)).toEqual(['email_token', 'user_id']);
  });
});

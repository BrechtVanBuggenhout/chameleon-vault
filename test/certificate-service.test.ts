import * as crypto from 'crypto';
import { jest, describe, it, expect, beforeEach } from '@jest/globals';

import { FirestoreRegistry } from '../src/gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../src/gcp/bigquery-lineage.js';
import { CloudKMSClient } from '../src/gcp/cloud-kms.js';
import { GCSClient } from '../src/gcp/gcs-client.js';
import { DeletionRequestRepository } from '../src/gcp/deletion-request-repository.js';
import { CertificateChainRepository } from '../src/gcp/certificate-chain-repository.js';
import { DeletionRequest } from '../src/types/deletion-request.js';
jest.mock('../src/services/registry.js', () => ({
  connectorRegistry: { getRegisteredConnectorNames: () => ['hubspot', 'salesforce'] },
}));
await jest.unstable_mockModule('../src/config/env.js', () => ({
  getRequiredEnv: jest.fn((key: string) => {
    switch (key) {
      case 'GCP_PROJECT_ID': return 'test-project';
      case 'FIRESTORE_DATABASE_ID': return 'test-db';
      default: return 'mock-value';
    }
  }),
}));

const { CertificateService } = await import('../src/services/certificate-service.js');

// A real PEM keypair -- getKeyFingerprint() runs crypto.createPublicKey()
// on whatever getPublicKey() returns, so a fake string won't do.
const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

describe('CertificateService - generateCertificateClaims', () => {
  let service: InstanceType<typeof CertificateService>;
  let mockFirestoreRegistry: { getKeyStatus: jest.Mock };
  let mockLineageRepo: { getGhostDataFindings: jest.Mock };
  let mockKmsClient: { getCryptoKeyPath: jest.Mock; getNewestEnabledVersion: jest.Mock; getPublicKey: jest.Mock };
  let mockDeletionRequestRepo: { getDeletionRequest: jest.Mock; getLatestCompletedDeletionRequestForUser: jest.Mock };
  let baseRequest: DeletionRequest;

  beforeEach(() => {
    baseRequest = {
      deletion_request_id: 'del-1',
      tenant_id: 'default-tenant',
      user_id: 'user-1',
      status: 'CASCADE_COMPLETE',
      created_at: new Date(),
      status_history: [],
      janitor_wipes: [],
    };

    mockFirestoreRegistry = {
      getKeyStatus: jest.fn().mockResolvedValue({ status: 'SHREDDED', created_at: '2026-01-01T00:00:00Z', shredAt: '2026-08-16T20:39:06.717Z' }),
    };
    mockLineageRepo = { getGhostDataFindings: jest.fn().mockResolvedValue([]) };
    mockKmsClient = {
      getCryptoKeyPath: jest.fn().mockReturnValue('projects/p/locations/l/keyRings/r/cryptoKeys/k'),
      getNewestEnabledVersion: jest.fn().mockResolvedValue('projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1'),
      getPublicKey: jest.fn().mockResolvedValue(publicKeyPem),
    };
    mockDeletionRequestRepo = {
      getDeletionRequest: jest.fn(async () => ({ ...baseRequest })),
      getLatestCompletedDeletionRequestForUser: jest.fn(async () => ({ ...baseRequest })),
    };

    service = new CertificateService(
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepo as unknown as BigQueryLineageRepository,
      mockKmsClient as unknown as CloudKMSClient,
      {} as unknown as GCSClient,
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      {} as unknown as CertificateChainRepository,
    );
  });

  it('labels a source-redaction wipe with rowsAffected: 0 as CONFIRMED_ABSENT, not ERASED', async () => {
    // Reproduces a real false-positive found live on Immoscoop 2026-08-17:
    // a REDACT_IN_PLACE UPDATE whose WHERE clause matched zero rows was
    // certified as "ERASED" because only janitor's recordsFound was
    // checked, never source-redaction's rowsAffected.
    baseRequest.janitor_wipes = [
      {
        destination: 'bigquery:immoscoop-datawarehouse-raw.DATA.agencyAndOfficeMigration',
        status: 'SUCCEEDED',
        updated_at: new Date('2026-08-16T20:39:06.717Z'),
        details: { rowsAffected: 0 },
      },
    ];

    const claims = await service.generateCertificateClaims('user-1', 'default-tenant', 'del-1');

    expect(claims.lineageSummary).toEqual([
      expect.objectContaining({
        system: 'bigquery:immoscoop-datawarehouse-raw.DATA.agencyAndOfficeMigration',
        status: 'CONFIRMED_ABSENT',
      }),
    ]);
  });

  it('still labels a real source-redaction wipe (rowsAffected > 0) as ERASED', async () => {
    baseRequest.janitor_wipes = [
      {
        destination: 'bigquery:acme.crm.contacts',
        status: 'SUCCEEDED',
        updated_at: new Date('2026-08-16T20:39:06.717Z'),
        details: { rowsAffected: 3 },
      },
    ];

    const claims = await service.generateCertificateClaims('user-1', 'default-tenant', 'del-1');

    expect(claims.lineageSummary).toEqual([
      expect.objectContaining({ system: 'bigquery:acme.crm.contacts', status: 'ERASED' }),
    ]);
  });

  it('still labels a janitor/SaaS wipe with recordsFound: 0 as CONFIRMED_ABSENT (existing behavior preserved)', async () => {
    baseRequest.janitor_wipes = [
      { destination: 'hubspot', status: 'SUCCEEDED', updated_at: new Date(), details: { recordsFound: 0 } },
    ];

    const claims = await service.generateCertificateClaims('user-1', 'default-tenant', 'del-1');

    expect(claims.lineageSummary).toEqual([
      expect.objectContaining({ system: 'hubspot', status: 'CONFIRMED_ABSENT' }),
    ]);
  });

  it('renders a real ISO timestamp for a plain Date, not "[object Object]"', async () => {
    const when = new Date('2026-08-16T20:39:06.717Z');
    baseRequest.janitor_wipes = [
      { destination: 'hubspot', status: 'SUCCEEDED', updated_at: when, details: {} },
    ];

    const claims = await service.generateCertificateClaims('user-1', 'default-tenant', 'del-1');

    expect(claims.lineageSummary[0].timestamp).toBe('2026-08-16T20:39:06.717Z');
  });

  it('renders a real ISO timestamp for a Firestore-Timestamp-shaped value, not "[object Object]"', async () => {
    // Reproduces the exact bug found in a real issued certificate: Firestore's
    // Node SDK reads timestamp fields back as its own Timestamp class, which
    // is not `instanceof Date` and has no toString() override -- String()
    // on it silently produces "[object Object]" instead of throwing.
    const when = new Date('2026-08-16T20:39:06.717Z');
    const firestoreTimestampShaped = { toDate: () => when };
    baseRequest.janitor_wipes = [
      { destination: 'hubspot', status: 'SUCCEEDED', updated_at: firestoreTimestampShaped as any, details: {} },
    ];

    const claims = await service.generateCertificateClaims('user-1', 'default-tenant', 'del-1');

    expect(claims.lineageSummary[0].timestamp).toBe('2026-08-16T20:39:06.717Z');
    expect(claims.lineageSummary[0].timestamp).not.toBe('[object Object]');
  });

  it('only ever includes SUCCEEDED wipes, never a FAILED one, in lineageSummary', async () => {
    baseRequest.janitor_wipes = [
      { destination: 'hubspot', status: 'SUCCEEDED', updated_at: new Date(), details: {} },
      { destination: 'salesforce', status: 'FAILED', updated_at: new Date(), details: { error: 'timeout' } },
    ];

    const claims = await service.generateCertificateClaims('user-1', 'default-tenant', 'del-1');

    expect(claims.lineageSummary).toHaveLength(1);
    expect(claims.lineageSummary[0].system).toBe('hubspot');
  });
});

import { jest, describe, it, expect, beforeEach } from '@jest/globals';

import { FirestoreRegistry } from '../src/gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../src/gcp/bigquery-lineage.js';
import { CloudKMSClient } from '../src/gcp/cloud-kms.js';
import { GCSClient } from '../src/gcp/gcs-client.js';
import { DeletionRequestRepository } from '../src/gcp/deletion-request-repository.js';
import { CertificateChainRepository } from '../src/gcp/certificate-chain-repository.js';
import { CertificateSigner } from '../src/certificate-signer/sign.js';
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

// A syntactically valid (unsigned) JWT-shaped string -- buildEvidentiaryStatus
// decodes this via jose's decodeJwt (no signature check) to read
// chainSequence, so the mock needs a real three-segment token, not just any
// string.
function fakeJwt(payload: Record<string, unknown>): string {
  const b64url = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${b64url({ alg: 'PS256' })}.${b64url(payload)}.fake-signature`;
}

// Real bug this replaced: findLatestCertificate used to probe 5 hardcoded
// demo user IDs and show whichever one it found first -- a real customer
// with real certificates saw "no certificates yet" regardless of their real
// history. This is the service-layer half of the real fix (Key Vault#86 --
// see DeletionRequestRepository.getMostRecentCertificateIssuedForTenant for
// the real Firestore query and its composite index).
describe('CertificateService.getLatestCertificateForTenant', () => {
  let service: InstanceType<typeof CertificateService>;
  let mockFirestoreRegistry: { getKeyStatus: jest.Mock };
  let mockLineageRepo: { getGhostDataFindings: jest.Mock };
  let mockKmsClient: {
    getCryptoKeyPath: jest.Mock;
    getNewestEnabledVersion: jest.Mock;
    getPublicKey: jest.Mock;
    asymmetricSign: jest.Mock;
  };
  let mockDeletionRequestRepo: {
    getMostRecentCertificateIssuedForTenant: jest.Mock;
    getLatestCompletedDeletionRequestForUser: jest.Mock;
  };
  let mockGcsClient: { downloadCertificate: jest.Mock };
  let baseRequest: DeletionRequest;

  beforeEach(() => {
    baseRequest = {
      deletion_request_id: 'del-1',
      tenant_id: 'acme-tenant',
      user_id: 'usr-real-042',
      status: 'CERTIFICATE_ISSUED',
      created_at: new Date('2026-09-01T00:00:00Z'),
      status_history: [],
      janitor_wipes: [],
      certificate_gcs_path: 'gs://bucket/acme-tenant/usr-real-042.json',
    };

    mockFirestoreRegistry = {
      getKeyStatus: jest.fn().mockResolvedValue({ status: 'SHREDDED', created_at: '2026-01-01T00:00:00Z', shredAt: '2026-09-01T00:00:00.000Z' }),
    };
    mockLineageRepo = { getGhostDataFindings: jest.fn().mockResolvedValue([]) };
    mockKmsClient = {
      getCryptoKeyPath: jest.fn().mockReturnValue('projects/p/locations/l/keyRings/r/cryptoKeys/k'),
      getNewestEnabledVersion: jest.fn().mockResolvedValue('projects/p/.../cryptoKeyVersions/1'),
      getPublicKey: jest.fn().mockResolvedValue('fake-pem'),
      asymmetricSign: jest.fn().mockResolvedValue('fake-signature-base64url'),
    };
    mockDeletionRequestRepo = {
      getMostRecentCertificateIssuedForTenant: jest.fn().mockResolvedValue(baseRequest),
      getLatestCompletedDeletionRequestForUser: jest.fn().mockResolvedValue(baseRequest),
    };
    mockGcsClient = {
      downloadCertificate: jest.fn().mockResolvedValue({
        certificate: fakeJwt({ sub: 'usr-real-042', chainSequence: 7, previousCertificateHash: 'abc123' }),
        tsaTimestamp: { status: 'OBTAINED' },
        rekorEntry: { status: 'PUBLISHED' },
      }),
    };

    service = new CertificateService(
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepo as unknown as BigQueryLineageRepository,
      mockKmsClient as unknown as CloudKMSClient,
      mockGcsClient as unknown as GCSClient,
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      {} as unknown as CertificateChainRepository,
      {} as unknown as CertificateSigner
    );
  });

  it('finds the tenant\'s most recent issued certificate and returns the real stored userId + certificate', async () => {
    const result = await service.getLatestCertificateForTenant('acme-tenant');

    expect(mockDeletionRequestRepo.getMostRecentCertificateIssuedForTenant).toHaveBeenCalledWith('acme-tenant');
    expect(result).toEqual({
      certificate: fakeJwt({ sub: 'usr-real-042', chainSequence: 7, previousCertificateHash: 'abc123' }),
      userId: 'usr-real-042',
      evidentiaryStatus: {
        hashChain: { linked: true, chainSequence: 7 },
        timestamp: 'OBTAINED',
        transparencyLog: 'PUBLISHED',
        hardwareAttestation: 'NOT_AVAILABLE',
      },
    });
  });

  it('delegates to getCertificateForUser for the actual retrieval -- not a separate, duplicated GCS read path', async () => {
    await service.getLatestCertificateForTenant('acme-tenant');

    // getCertificateForUser's own real gate (assertCascadeComplete) runs via
    // this exact call -- proven by it actually reading the deletion request
    // for the discovered user, not just trusting the tenant-level lookup.
    expect(mockDeletionRequestRepo.getLatestCompletedDeletionRequestForUser).toHaveBeenCalledWith('usr-real-042', 'acme-tenant');
    expect(mockGcsClient.downloadCertificate).toHaveBeenCalledWith('gs://bucket/acme-tenant/usr-real-042.json');
  });

  it('returns null -- not a fixture, not an error -- when the tenant has never had a certificate issued', async () => {
    mockDeletionRequestRepo.getMostRecentCertificateIssuedForTenant.mockResolvedValue(null);

    const result = await service.getLatestCertificateForTenant('brand-new-tenant');

    expect(result).toBeNull();
    expect(mockGcsClient.downloadCertificate).not.toHaveBeenCalled();
  });

  it('defaults to default-tenant when no tenantId is given, same as every other tenant-scoped method on this service', async () => {
    await service.getLatestCertificateForTenant();

    expect(mockDeletionRequestRepo.getMostRecentCertificateIssuedForTenant).toHaveBeenCalledWith('default-tenant');
  });
});

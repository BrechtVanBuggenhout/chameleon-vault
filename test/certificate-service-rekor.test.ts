import * as crypto from 'crypto';
import { jest, describe, it, expect, beforeEach } from '@jest/globals';

import { FirestoreRegistry } from '../src/gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../src/gcp/bigquery-lineage.js';
import { CloudKMSClient } from '../src/gcp/cloud-kms.js';
import { GCSClient } from '../src/gcp/gcs-client.js';
import { DeletionRequestRepository } from '../src/gcp/deletion-request-repository.js';
import { CertificateChainRepository } from '../src/gcp/certificate-chain-repository.js';
import { RekorClient, RekorLogEntryInfo } from '../src/gcp/rekor-client.js';
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

const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

describe('CertificateService.issueAndStoreCertificate -- Rekor integration', () => {
  let service: InstanceType<typeof CertificateService>;
  let mockFirestoreRegistry: { getKeyStatus: jest.Mock };
  let mockLineageRepo: { getGhostDataFindings: jest.Mock };
  let mockKmsClient: {
    getCryptoKeyPath: jest.Mock;
    getNewestEnabledVersion: jest.Mock;
    getPublicKey: jest.Mock;
    asymmetricSign: jest.Mock;
  };
  let mockDeletionRequestRepo: { getDeletionRequest: jest.Mock; getLatestCompletedDeletionRequestForUser: jest.Mock };
  let mockChainRepository: { appendToChain: jest.Mock; recordTsaTimestamp: jest.Mock; recordRekorEntry: jest.Mock };
  let mockGcsClient: { uploadCertificate: jest.Mock };
  let mockRekorClient: { publishCertificateHash: jest.Mock };
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
      certificate_gcs_path: undefined,
    };

    mockFirestoreRegistry = {
      getKeyStatus: jest.fn().mockResolvedValue({ status: 'SHREDDED', created_at: '2026-01-01T00:00:00Z', shredAt: '2026-08-29T00:00:00.000Z' }),
    };
    mockLineageRepo = { getGhostDataFindings: jest.fn().mockResolvedValue([]) };
    mockKmsClient = {
      getCryptoKeyPath: jest.fn().mockReturnValue('projects/p/locations/l/keyRings/r/cryptoKeys/k'),
      getNewestEnabledVersion: jest.fn().mockResolvedValue('projects/p/.../cryptoKeyVersions/1'),
      getPublicKey: jest.fn().mockResolvedValue(publicKeyPem),
      asymmetricSign: jest.fn().mockResolvedValue('fake-signature-base64url'),
    };
    mockDeletionRequestRepo = {
      getDeletionRequest: jest.fn(async () => ({ ...baseRequest })),
      getLatestCompletedDeletionRequestForUser: jest.fn(async () => ({ ...baseRequest })),
    };
    mockChainRepository = {
      appendToChain: jest.fn(async (_tenantId: string, _deletionRequestId: string, sign: (p: string | null, s: number) => Promise<{ certificate: string; certificateHash: string }>) => {
        const result = await sign(null, 1);
        return { ...result, previousHash: null, sequence: 1 };
      }),
      recordTsaTimestamp: jest.fn().mockResolvedValue(undefined),
      recordRekorEntry: jest.fn().mockResolvedValue(undefined),
    };
    mockGcsClient = { uploadCertificate: jest.fn().mockResolvedValue('gs://bucket/path.json') };
    mockRekorClient = { publishCertificateHash: jest.fn() };

    service = new CertificateService(
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepo as unknown as BigQueryLineageRepository,
      mockKmsClient as unknown as CloudKMSClient,
      mockGcsClient as unknown as GCSClient,
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      mockChainRepository as unknown as CertificateChainRepository,
      undefined, // tsaClient
      mockRekorClient as unknown as RekorClient
    );
  });

  it('publishes certificateHash/previousHash to Rekor, persists the result, and passes it through to GCS', async () => {
    const rekorEntry: RekorLogEntryInfo = {
      status: 'PUBLISHED',
      entryUuid: 'entry-uuid-123',
      logIndex: 42,
      rekorUrl: 'https://rekor.sigstore.dev',
      attemptedAt: '2026-08-29T00:00:00.000Z',
    };
    mockRekorClient.publishCertificateHash.mockResolvedValue(rekorEntry);

    const result = await service.issueAndStoreCertificate('user-1', 'del-1');

    expect(result.certificate).toBeTruthy();

    // Called with the certificate's own hash and previousHash -- never
    // tenantId/userId, matching the by-hash lookup's same principle.
    expect(mockRekorClient.publishCertificateHash).toHaveBeenCalledWith(expect.any(String), null);

    expect(mockChainRepository.recordRekorEntry).toHaveBeenCalledWith(expect.any(String), rekorEntry);

    expect(mockGcsClient.uploadCertificate).toHaveBeenCalledWith(
      'user-1', 'del-1', expect.any(String), expect.any(String), 'default-tenant',
      expect.any(Object), undefined, rekorEntry
    );
  });

  it('still succeeds when the Rekor publish resolves to FAILED -- issuance is never blocked', async () => {
    const failed: RekorLogEntryInfo = {
      status: 'FAILED',
      rekorUrl: 'https://rekor.sigstore.dev',
      attemptedAt: '2026-08-29T00:00:00.000Z',
      error: 'HTTP 400',
    };
    mockRekorClient.publishCertificateHash.mockResolvedValue(failed);

    const result = await service.issueAndStoreCertificate('user-1', 'del-1');

    expect(result.certificate).toBeTruthy();
    expect(mockGcsClient.uploadCertificate).toHaveBeenCalledWith(
      'user-1', 'del-1', expect.any(String), expect.any(String), 'default-tenant',
      expect.any(Object), undefined, failed
    );
  });

  it('still succeeds even if the best-effort Firestore follow-up write itself rejects', async () => {
    mockRekorClient.publishCertificateHash.mockResolvedValue({
      status: 'PUBLISHED', entryUuid: 'x', logIndex: 1, rekorUrl: 'x', attemptedAt: 'x',
    });
    mockChainRepository.recordRekorEntry.mockRejectedValue(new Error('Firestore unavailable'));

    await expect(service.issueAndStoreCertificate('user-1', 'del-1')).resolves.toEqual(
      expect.objectContaining({ certificate: expect.any(String), gcsPath: 'gs://bucket/path.json' })
    );
    expect(mockGcsClient.uploadCertificate).toHaveBeenCalled();
  });

  it('never calls Rekor and never touches the chain-entry when rekorClient is not configured (disabled)', async () => {
    const disabledService = new CertificateService(
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepo as unknown as BigQueryLineageRepository,
      mockKmsClient as unknown as CloudKMSClient,
      mockGcsClient as unknown as GCSClient,
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      mockChainRepository as unknown as CertificateChainRepository
      // tsaClient and rekorClient both omitted
    );

    await disabledService.issueAndStoreCertificate('user-1', 'del-1');

    expect(mockRekorClient.publishCertificateHash).not.toHaveBeenCalled();
    expect(mockChainRepository.recordRekorEntry).not.toHaveBeenCalled();
    expect(mockGcsClient.uploadCertificate).toHaveBeenCalledWith(
      'user-1', 'del-1', expect.any(String), expect.any(String), 'default-tenant',
      expect.any(Object), undefined, undefined
    );
  });
});

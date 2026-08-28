import * as crypto from 'crypto';
import { jest, describe, it, expect, beforeEach } from '@jest/globals';

import { FirestoreRegistry } from '../src/gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../src/gcp/bigquery-lineage.js';
import { CloudKMSClient } from '../src/gcp/cloud-kms.js';
import { GCSClient } from '../src/gcp/gcs-client.js';
import { DeletionRequestRepository } from '../src/gcp/deletion-request-repository.js';
import { CertificateChainRepository } from '../src/gcp/certificate-chain-repository.js';
import { TsaClient, TsaTimestampInfo } from '../src/gcp/tsa-client.js';
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

describe('CertificateService.issueAndStoreCertificate -- TSA integration', () => {
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
  let mockChainRepository: { appendToChain: jest.Mock; recordTsaTimestamp: jest.Mock };
  let mockGcsClient: { uploadCertificate: jest.Mock };
  let mockTsaClient: { requestTimestamp: jest.Mock };
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
      getKeyStatus: jest.fn().mockResolvedValue({ status: 'SHREDDED', created_at: '2026-01-01T00:00:00Z', shredAt: '2026-08-28T00:00:00.000Z' }),
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
    // Mirrors the real appendToChain's contract: invokes `sign`, returns its
    // result plus previousHash/sequence.
    mockChainRepository = {
      appendToChain: jest.fn(async (_tenantId: string, _deletionRequestId: string, sign: (p: string | null, s: number) => Promise<{ certificate: string; certificateHash: string }>) => {
        const result = await sign(null, 1);
        return { ...result, previousHash: null, sequence: 1 };
      }),
      recordTsaTimestamp: jest.fn().mockResolvedValue(undefined),
    };
    mockGcsClient = { uploadCertificate: jest.fn().mockResolvedValue('gs://bucket/path.json') };
    mockTsaClient = { requestTimestamp: jest.fn() };

    service = new CertificateService(
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepo as unknown as BigQueryLineageRepository,
      mockKmsClient as unknown as CloudKMSClient,
      mockGcsClient as unknown as GCSClient,
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      mockChainRepository as unknown as CertificateChainRepository,
      mockTsaClient as unknown as TsaClient
    );
  });

  it('succeeds and passes the OBTAINED timestamp through to GCS when the TSA succeeds', async () => {
    const timestamp: TsaTimestampInfo = {
      status: 'OBTAINED',
      token: 'base64token',
      timestamp: '2026-08-28T00:00:00.000Z',
      tsaUrl: 'https://freetsa.org/tsr',
      attemptedAt: '2026-08-28T00:00:00.000Z',
    };
    mockTsaClient.requestTimestamp.mockResolvedValue(timestamp);

    const result = await service.issueAndStoreCertificate('user-1', 'del-1');

    expect(result.certificate).toBeTruthy();
    expect(mockChainRepository.recordTsaTimestamp).toHaveBeenCalledWith(expect.any(String), timestamp);
    expect(mockGcsClient.uploadCertificate).toHaveBeenCalledWith(
      'user-1', 'del-1', expect.any(String), expect.any(String), 'default-tenant',
      expect.any(Object), timestamp
    );
  });

  it('still succeeds when the TSA call resolves to FAILED', async () => {
    const failed: TsaTimestampInfo = {
      status: 'FAILED',
      tsaUrl: 'https://freetsa.org/tsr',
      attemptedAt: '2026-08-28T00:00:00.000Z',
      error: 'timeout',
    };
    mockTsaClient.requestTimestamp.mockResolvedValue(failed);

    const result = await service.issueAndStoreCertificate('user-1', 'del-1');

    expect(result.certificate).toBeTruthy();
    expect(mockGcsClient.uploadCertificate).toHaveBeenCalledWith(
      'user-1', 'del-1', expect.any(String), expect.any(String), 'default-tenant',
      expect.any(Object), failed
    );
  });

  it('still succeeds even if the best-effort Firestore follow-up write itself rejects', async () => {
    mockTsaClient.requestTimestamp.mockResolvedValue({
      status: 'OBTAINED', token: 'x', timestamp: 'x', tsaUrl: 'x', attemptedAt: 'x',
    });
    mockChainRepository.recordTsaTimestamp.mockRejectedValue(new Error('Firestore unavailable'));

    await expect(service.issueAndStoreCertificate('user-1', 'del-1')).resolves.toEqual(
      expect.objectContaining({ certificate: expect.any(String), gcsPath: 'gs://bucket/path.json' })
    );
    // Issuance succeeded despite the rejection -- GCS upload still happened.
    expect(mockGcsClient.uploadCertificate).toHaveBeenCalled();
  });

  it('never calls the TSA and never touches the chain-entry when tsaClient is not configured (disabled)', async () => {
    const disabledService = new CertificateService(
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepo as unknown as BigQueryLineageRepository,
      mockKmsClient as unknown as CloudKMSClient,
      mockGcsClient as unknown as GCSClient,
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      mockChainRepository as unknown as CertificateChainRepository
      // tsaClient omitted entirely
    );

    await disabledService.issueAndStoreCertificate('user-1', 'del-1');

    expect(mockTsaClient.requestTimestamp).not.toHaveBeenCalled();
    expect(mockChainRepository.recordTsaTimestamp).not.toHaveBeenCalled();
    expect(mockGcsClient.uploadCertificate).toHaveBeenCalledWith(
      'user-1', 'del-1', expect.any(String), expect.any(String), 'default-tenant',
      expect.any(Object), undefined
    );
  });
});

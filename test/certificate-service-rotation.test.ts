import { jest, describe, it, expect, beforeEach } from '@jest/globals';

import { FirestoreRegistry } from '../src/gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../src/gcp/bigquery-lineage.js';
import { CloudKMSClient } from '../src/gcp/cloud-kms.js';
import { GCSClient } from '../src/gcp/gcs-client.js';
import { DeletionRequestRepository } from '../src/gcp/deletion-request-repository.js';
import { CertificateChainRepository } from '../src/gcp/certificate-chain-repository.js';
import { CertificateSigner } from '../src/certificate-signer/sign.js';

const mockLoggerInfo = jest.fn();
await jest.unstable_mockModule('../src/logging/index.js', () => ({
  createLogger: () => ({ info: mockLoggerInfo, error: jest.fn(), warn: jest.fn(), debug: jest.fn() }),
}));
await jest.unstable_mockModule('../src/config/env.js', () => ({
  getRequiredEnv: jest.fn((key: string) => (key === 'GCP_PROJECT_ID' ? 'test-project' : 'mock-value')),
}));

const { CertificateService } = await import('../src/services/certificate-service.js');

describe('CertificateService.rotateSigningKey audit trail', () => {
  let service: InstanceType<typeof CertificateService>;
  let mockKmsClient: {
    getCryptoKeyPath: jest.Mock;
    getNewestEnabledVersion: jest.Mock;
    createKeyVersion: jest.Mock;
    waitForVersionEnabled: jest.Mock;
  };

  beforeEach(() => {
    mockLoggerInfo.mockClear();
    mockKmsClient = {
      getCryptoKeyPath: jest.fn().mockReturnValue('projects/p/locations/l/keyRings/r/cryptoKeys/k'),
      getNewestEnabledVersion: jest.fn().mockResolvedValue('projects/p/.../cryptoKeyVersions/1'),
      createKeyVersion: jest.fn().mockResolvedValue('projects/p/.../cryptoKeyVersions/2'),
      waitForVersionEnabled: jest.fn().mockResolvedValue(undefined),
    };

    service = new CertificateService(
      {} as unknown as FirestoreRegistry,
      {} as unknown as BigQueryLineageRepository,
      mockKmsClient as unknown as CloudKMSClient,
      {} as unknown as GCSClient,
      {} as unknown as DeletionRequestRepository,
      {} as unknown as CertificateChainRepository,
      // rotateSigningKey() also invalidates certificateSigner's own,
      // separate cache -- see certificate-signer/sign.ts.
      { invalidateSigningKeyCache: jest.fn() } as unknown as CertificateSigner
    );
  });

  it('logs rotation with the same tamper-evident marker certificate issuance uses', async () => {
    await service.rotateSigningKey();

    expect(mockLoggerInfo).toHaveBeenCalledWith(
      expect.objectContaining({
        certificateChainAnchor: true,
        auditEventType: 'signing_key_rotated',
        previousVersion: 'projects/p/.../cryptoKeyVersions/1',
        newVersion: 'projects/p/.../cryptoKeyVersions/2',
      }),
      'Signing key rotated'
    );
  });

  it('mints a version and waits for it to be enabled before returning', async () => {
    const result = await service.rotateSigningKey();

    expect(mockKmsClient.createKeyVersion).toHaveBeenCalledWith('projects/p/locations/l/keyRings/r/cryptoKeys/k');
    expect(mockKmsClient.waitForVersionEnabled).toHaveBeenCalledWith('projects/p/.../cryptoKeyVersions/2');
    expect(result).toEqual({
      newVersion: 'projects/p/.../cryptoKeyVersions/2',
      previousVersion: 'projects/p/.../cryptoKeyVersions/1',
    });
  });
});

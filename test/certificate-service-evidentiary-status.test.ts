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
// chainSequence, so tests need a real three-segment token, not just any
// string.
function fakeJwt(payload: Record<string, unknown>): string {
  const b64url = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${b64url({ alg: 'PS256' })}.${b64url(payload)}.fake-signature`;
}

// This is the direct-coverage suite for getCertificateForUser -- previously
// it was only exercised indirectly, via getLatestCertificateForTenant's own
// test suite (certificate-service-latest.test.ts), which only ever covers
// the "stored" branch. The unchained-fallback branch (a request that hasn't
// reached CERTIFICATE_ISSUED yet) had no test coverage at all before this.
describe('CertificateService.getCertificateForUser -- evidentiaryStatus', () => {
  let service: InstanceType<typeof CertificateService>;
  let mockFirestoreRegistry: { getKeyStatus: jest.Mock };
  let mockLineageRepo: { getGhostDataFindings: jest.Mock };
  let mockKmsClient: Record<string, jest.Mock>;
  let mockDeletionRequestRepo: { getLatestCompletedDeletionRequestForUser: jest.Mock };
  let mockGcsClient: { downloadCertificate: jest.Mock };
  let mockCertificateSigner: { generateClaims: jest.Mock; signClaims: jest.Mock };
  let baseRequest: DeletionRequest;

  beforeEach(() => {
    baseRequest = {
      deletion_request_id: 'del-1',
      tenant_id: 'default-tenant',
      user_id: 'user-1',
      status: 'CERTIFICATE_ISSUED',
      created_at: new Date(),
      status_history: [],
      janitor_wipes: [],
      certificate_gcs_path: 'gs://bucket/user-1.json',
    };

    mockFirestoreRegistry = {
      getKeyStatus: jest.fn().mockResolvedValue({ status: 'SHREDDED', created_at: '2026-01-01T00:00:00Z', shredAt: '2026-09-01T00:00:00.000Z' }),
    };
    mockLineageRepo = { getGhostDataFindings: jest.fn().mockResolvedValue([]) };
    mockKmsClient = {};
    mockDeletionRequestRepo = {
      getLatestCompletedDeletionRequestForUser: jest.fn(async () => ({ ...baseRequest })),
    };
    mockGcsClient = { downloadCertificate: jest.fn() };
    mockCertificateSigner = {
      generateClaims: jest.fn().mockResolvedValue({ sub: 'user-1' }),
      signClaims: jest.fn().mockResolvedValue({ certificate: fakeJwt({ sub: 'user-1', chainSequence: null, previousCertificateHash: null }) }),
    };

    service = new CertificateService(
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepo as unknown as BigQueryLineageRepository,
      mockKmsClient as unknown as CloudKMSClient,
      mockGcsClient as unknown as GCSClient,
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      {} as unknown as CertificateChainRepository,
      mockCertificateSigner as unknown as CertificateSigner
    );
  });

  it('reports full evidence when the stored certificate has a real timestamp and transparency-log entry', async () => {
    mockGcsClient.downloadCertificate.mockResolvedValue({
      certificate: fakeJwt({ sub: 'user-1', chainSequence: 12, previousCertificateHash: 'prev-hash' }),
      tsaTimestamp: { status: 'OBTAINED' },
      rekorEntry: { status: 'PUBLISHED' },
    });

    const result = await service.getCertificateForUser('user-1');

    expect(result.stored).toBe(true);
    expect(result.evidentiaryStatus).toEqual({
      hashChain: { linked: true, chainSequence: 12 },
      timestamp: 'OBTAINED',
      transparencyLog: 'PUBLISHED',
      hardwareAttestation: 'NOT_AVAILABLE',
    });
  });

  it('reports FAILED for a mechanism that was attempted but failed, distinct from never attempted', async () => {
    mockGcsClient.downloadCertificate.mockResolvedValue({
      certificate: fakeJwt({ sub: 'user-1', chainSequence: 3, previousCertificateHash: 'prev-hash' }),
      tsaTimestamp: { status: 'FAILED' },
      // rekorEntry omitted entirely -- e.g. rekorClient wasn't configured
      // at issuance time.
    });

    const result = await service.getCertificateForUser('user-1');

    expect(result.evidentiaryStatus.timestamp).toBe('FAILED');
    expect(result.evidentiaryStatus.transparencyLog).toBe('NOT_ATTEMPTED');
  });

  it('reports NOT_ATTEMPTED for both when a stored certificate predates TSA/Rekor instrumentation entirely', async () => {
    mockGcsClient.downloadCertificate.mockResolvedValue({
      certificate: fakeJwt({ sub: 'user-1', chainSequence: 1, previousCertificateHash: null }),
    });

    const result = await service.getCertificateForUser('user-1');

    expect(result.evidentiaryStatus.timestamp).toBe('NOT_ATTEMPTED');
    expect(result.evidentiaryStatus.transparencyLog).toBe('NOT_ATTEMPTED');
    expect(result.evidentiaryStatus.hashChain).toEqual({ linked: true, chainSequence: 1 });
  });

  it('reports not-linked and NOT_ATTEMPTED across the board for the unchained fallback certificate', async () => {
    // Request hasn't reached CERTIFICATE_ISSUED yet -- getCertificateForUser
    // signs a fresh, deliberately unchained certificate on the fly. Nothing
    // failed here; nothing was ever attempted, which is exactly why this
    // must not report FAILED.
    baseRequest.status = 'CASCADE_COMPLETE';
    baseRequest.certificate_gcs_path = undefined;

    const result = await service.getCertificateForUser('user-1');

    expect(result.stored).toBe(false);
    expect(mockGcsClient.downloadCertificate).not.toHaveBeenCalled();
    expect(result.evidentiaryStatus).toEqual({
      hashChain: { linked: false, chainSequence: null },
      timestamp: 'NOT_ATTEMPTED',
      transparencyLog: 'NOT_ATTEMPTED',
      hardwareAttestation: 'NOT_AVAILABLE',
    });
  });

  it('falls back to not-linked, without throwing, if the stored certificate is somehow not a well-formed JWT', async () => {
    mockGcsClient.downloadCertificate.mockResolvedValue({
      certificate: 'not-actually-a-jwt',
      tsaTimestamp: { status: 'OBTAINED' },
      rekorEntry: { status: 'PUBLISHED' },
    });

    const result = await service.getCertificateForUser('user-1');

    // Certificate retrieval itself must never break because of this --
    // only the derived hash-chain field degrades.
    expect(result.certificate).toBe('not-actually-a-jwt');
    expect(result.evidentiaryStatus.hashChain).toEqual({ linked: false, chainSequence: null });
    // The mechanisms that don't depend on decoding the JWT are unaffected.
    expect(result.evidentiaryStatus.timestamp).toBe('OBTAINED');
    expect(result.evidentiaryStatus.transparencyLog).toBe('PUBLISHED');
  });

  it('always reports hardwareAttestation as NOT_AVAILABLE -- no code path produces real attestation data today', async () => {
    mockGcsClient.downloadCertificate.mockResolvedValue({
      certificate: fakeJwt({ sub: 'user-1', chainSequence: 1, previousCertificateHash: null }),
    });

    const result = await service.getCertificateForUser('user-1');

    expect(result.evidentiaryStatus.hardwareAttestation).toBe('NOT_AVAILABLE');
  });
});

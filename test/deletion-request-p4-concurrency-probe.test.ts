import { DeletionRequest, DeletionRequestStatus } from '../src/types/deletion-request.js';
import { jest, describe, it, expect } from '@jest/globals';

import { DeletionRequestRepository } from '../src/gcp/deletion-request-repository.js';
import { FirestoreRegistry } from '../src/gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../src/gcp/bigquery-lineage.js';
import { JanitorService } from '../src/services/janitor.js';
import { CloudKMSClient } from '../src/gcp/cloud-kms.js';
import { CertificateService } from '../src/services/certificate-service.js';
jest.mock('../src/gcp/deletion-request-repository.js');
jest.mock('../src/gcp/firestore-registry.js');
jest.mock('../src/gcp/bigquery-lineage.js');
jest.mock('../src/services/janitor.js');
jest.mock('../src/gcp/cloud-kms.js');
jest.mock('../src/services/certificate-service.js');
await jest.unstable_mockModule('../src/config/env.js', () => ({
  getRequiredEnv: jest.fn((key: string) => {
    switch (key) {
      case 'GCP_PROJECT_ID': return 'test-project';
      case 'FIRESTORE_DATABASE_ID': return 'test-db';
      case 'FIRESTORE_DELETION_REQUEST_COLLECTION': return 'deletion_requests';
      case 'FIRESTORE_COLLECTION': return 'user_keys';
      case 'CLOUD_KMS_REGION': return 'us-central1';
      case 'CLOUD_KMS_KEY_RING': return 'test-keyring';
      case 'CLOUD_KMS_KEY_NAME': return 'test-key';
      case 'CLOUD_KMS_SIGNING_KEY_RING': return 'test-signing-keyring';
      case 'CLOUD_KMS_SIGNING_KEY_NAME': return 'test-signing-key';
      default: return 'mock-value';
    }
  }),
}));

const { DeletionRequestService } = await import('../src/services/deletion-request-service.js');

/**
 * REGRESSION TEST for CSC699 Week 1's P4 finding: advanceRequest's
 * read -> validate -> act -> write sequence let two concurrent callers both
 * pass validation off the same stale read and both complete the
 * safety-critical CASCADE_COMPLETE -> CERTIFICATE_ISSUED transition,
 * minting two valid, chained certificates for one deletion event.
 *
 * Before the fix (claimTransition's atomic compare-and-swap), this exact
 * test asserted `issueAndStoreCertificate` was called twice -- confirming
 * the race was real, not hypothetical. It now asserts exactly once: the
 * loser's claimTransition call sees the winner's already-written status
 * and backs off before ever calling the certificate service.
 *
 * getDeletionRequest is deliberately still a stale, non-stateful mock (it
 * always returns the same pre-write snapshot) -- the race window this
 * models (two independent reads landing before either write is durably
 * visible) is real and still exists. What closes the race is
 * claimTransition's own atomicity, checked against `trueStatus` below
 * (standing in for the transactional document Firestore actually
 * guards), not a fix to the read.
 */
describe('DeletionRequestService P4: concurrent advance-to-CERTIFICATE_ISSUED', () => {
  it('issues exactly one certificate when two callers race off the same stale CASCADE_COMPLETE read', async () => {
    const staleRequest: DeletionRequest = {
      deletion_request_id: 'race-1',
      tenant_id: 'default-tenant',
      user_id: 'user-race',
      status: 'CASCADE_COMPLETE' as DeletionRequestStatus,
      created_at: new Date(),
      status_history: [],
      janitor_wipes: [],
    };

    // Stands in for the one real field a Firestore transaction actually
    // guards atomicity over -- separate from staleRequest, which never
    // changes, so getDeletionRequest keeps handing out the same pre-write
    // snapshot to both callers exactly as the real repository's two
    // independent (non-transactional) reads would.
    let trueStatus: DeletionRequestStatus = 'CASCADE_COMPLETE';

    const mockDeletionRequestRepo = {
      getDeletionRequest: jest.fn(async () => ({ ...staleRequest })),
      claimTransition: jest.fn(async (
        _id: string,
        allowedFromStatuses: DeletionRequestStatus[],
        newStatus: DeletionRequestStatus
      ) => {
        if (!allowedFromStatuses.includes(trueStatus)) {
          return { claimed: false, current: { ...staleRequest, status: trueStatus } };
        }
        trueStatus = newStatus;
        return { claimed: true };
      }),
      updateDeletionRequestFields: jest.fn().mockResolvedValue(undefined),
      updateDeletionRequestStatus: jest.fn().mockResolvedValue(undefined),
    } as unknown as jest.Mocked<DeletionRequestRepository>;

    const mockFirestoreRegistry = {} as unknown as jest.Mocked<FirestoreRegistry>;
    const mockLineageRepository = {
      recordEvent: jest.fn().mockResolvedValue(undefined),
    } as unknown as jest.Mocked<BigQueryLineageRepository>;
    const mockJanitorService = {} as unknown as jest.Mocked<JanitorService>;
    const mockDekKmsClient = {} as unknown as jest.Mocked<CloudKMSClient>;
    const mockCertificateService = {
      issueAndStoreCertificate: jest.fn().mockResolvedValue({
        certificate: 'fake-jwt',
        gcsPath: 'gs://fake-bucket/fake-cert.json',
      }),
    } as unknown as jest.Mocked<CertificateService>;

    const service = new DeletionRequestService(
      mockDeletionRequestRepo,
      mockFirestoreRegistry,
      mockLineageRepository,
      mockJanitorService,
      mockDekKmsClient,
      mockCertificateService
    );

    await Promise.all([
      service.advanceRequest('race-1', 'CERTIFICATE_ISSUED', 'op-a'),
      service.advanceRequest('race-1', 'CERTIFICATE_ISSUED', 'op-b'),
    ]);

    // The fix: claimTransition's atomic compare-and-swap means only the
    // winner ever reaches issueAndStoreCertificate. The loser's
    // claimTransition call observes trueStatus already moved past
    // CASCADE_COMPLETE and returns early instead of re-running the handler.
    expect(mockCertificateService.issueAndStoreCertificate).toHaveBeenCalledTimes(1);
    expect(mockDeletionRequestRepo.claimTransition).toHaveBeenCalledTimes(2);
  });
});

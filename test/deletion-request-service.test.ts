import { DeletionRequest, DeletionRequestStatus } from '../src/types/deletion-request.js';
import { jest, describe, it, expect, beforeEach } from '@jest/globals';

// Mock dependencies
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

describe('DeletionRequestService - State Transition Matrix', () => {
  let service: DeletionRequestService;
  let mockDeletionRequestRepo: jest.Mocked<DeletionRequestRepository>;
  let mockFirestoreRegistry: jest.Mocked<FirestoreRegistry>;
  let mockLineageRepository: jest.Mocked<BigQueryLineageRepository>;
  let mockJanitorService: jest.Mocked<JanitorService>;
  let mockDekKmsClient: jest.Mocked<CloudKMSClient>;
  let mockCertificateService: jest.Mocked<CertificateService>;

  beforeEach(() => {
    jest.clearAllMocks(); // Clear mocks before each test to ensure isolation

    // Instantiate the mocked dependencies
    mockDeletionRequestRepo = new (DeletionRequestRepository as jest.Mock)();
    mockFirestoreRegistry = new (FirestoreRegistry as jest.Mock)();
    mockLineageRepository = new (BigQueryLineageRepository as jest.Mock)();
    mockJanitorService = new (JanitorService as jest.Mock)();
    mockDekKmsClient = new (CloudKMSClient as jest.Mock)();
    mockCertificateService = new (CertificateService as jest.Mock)();

    // Instantiate the service with the mocked dependencies
    service = new DeletionRequestService(
      mockDeletionRequestRepo, mockFirestoreRegistry, mockLineageRepository, mockJanitorService, mockDekKmsClient, mockCertificateService
    );
  });

  // Helper to access private method for testing
  const callIsValidTransition = (currentStatus: DeletionRequestStatus, newStatus: DeletionRequestStatus): boolean => {
    // @ts-ignore - Accessing private method for testing purposes
    return service.isValidTransition(currentStatus, newStatus);
  };

  it('should allow valid transitions', () => {
    expect(callIsValidTransition('SHRED_REQUESTED', 'KEY_DESTROYED')).toBe(true);
    expect(callIsValidTransition('SHRED_REQUESTED', 'CASCADE_PARTIAL_FAILURE')).toBe(true);

    expect(callIsValidTransition('KEY_DESTROYED', 'CASCADE_PENDING')).toBe(true);
    expect(callIsValidTransition('KEY_DESTROYED', 'CASCADE_PARTIAL_FAILURE')).toBe(true);

    expect(callIsValidTransition('CASCADE_PENDING', 'CASCADE_IN_PROGRESS')).toBe(true);
    expect(callIsValidTransition('CASCADE_PENDING', 'CASCADE_PARTIAL_FAILURE')).toBe(true);

    expect(callIsValidTransition('CASCADE_IN_PROGRESS', 'CASCADE_COMPLETE')).toBe(true);
    expect(callIsValidTransition('CASCADE_IN_PROGRESS', 'CASCADE_PARTIAL_FAILURE')).toBe(true);

    expect(callIsValidTransition('CASCADE_PARTIAL_FAILURE', 'CASCADE_IN_PROGRESS')).toBe(true);
    expect(callIsValidTransition('CASCADE_PARTIAL_FAILURE', 'SHRED_REQUESTED')).toBe(true); // Allow retry from start

    expect(callIsValidTransition('CASCADE_COMPLETE', 'CERTIFICATE_ISSUED')).toBe(true);
    expect(callIsValidTransition('CASCADE_COMPLETE', 'CASCADE_PARTIAL_FAILURE')).toBe(true);
  });

  it('should disallow invalid transitions', () => {
    // Skipping states
    expect(callIsValidTransition('SHRED_REQUESTED', 'CASCADE_PENDING')).toBe(false);
    // Update: KEY_DESTROYED -> CERTIFICATE_ISSUED is now allowed for users without SaaS lineage
    expect(callIsValidTransition('KEY_DESTROYED', 'CERTIFICATE_ISSUED')).toBe(true);

    // Going backwards (except for retry from CASCADE_PARTIAL_FAILURE)
    expect(callIsValidTransition('CASCADE_COMPLETE', 'SHRED_REQUESTED')).toBe(false);
    expect(callIsValidTransition('CERTIFICATE_ISSUED', 'KEY_DESTROYED')).toBe(false);
    expect(callIsValidTransition('CERTIFICATE_ISSUED', 'CASCADE_COMPLETE')).toBe(false);

    // Big jumps
    expect(callIsValidTransition('SHRED_REQUESTED', 'CERTIFICATE_ISSUED')).toBe(false);
  });

  it('should not allow transitions from a terminal state (CERTIFICATE_ISSUED)', () => {
    expect(callIsValidTransition('CERTIFICATE_ISSUED', 'SHRED_REQUESTED')).toBe(false);
    expect(callIsValidTransition('CERTIFICATE_ISSUED', 'KEY_DESTROYED')).toBe(false);
    expect(callIsValidTransition('CERTIFICATE_ISSUED', 'CASCADE_COMPLETE')).toBe(false);
  });
});

describe('DeletionRequestService - cascade outcome gates certificate issuance', () => {
  // NOTE: this suite builds plain jest.fn() mocks directly rather than
  // relying on jest.mock(...) automocking of the real classes. Under
  // ts-jest's ESM preset, automock does not actually wrap async prototype
  // methods as jest mock functions (confirmed: jest.isMockFunction() is
  // false on them), so `.mockResolvedValue`/`.mockImplementation` throw.
  // This matches the manual-mock-class pattern already used in
  // api.integration.test.ts for the same reason.
  let service: DeletionRequestService;
  let mockDeletionRequestRepo: { [K in keyof DeletionRequestRepository]: jest.Mock };
  let mockFirestoreRegistry: { [K in keyof FirestoreRegistry]: jest.Mock };
  let mockLineageRepository: { [K in keyof BigQueryLineageRepository]: jest.Mock };
  let mockJanitorService: { [K in keyof JanitorService]: jest.Mock };
  let mockDekKmsClient: { [K in keyof CloudKMSClient]: jest.Mock };
  let mockCertificateService: { [K in keyof CertificateService]: jest.Mock };
  let currentRequest: DeletionRequest;

  beforeEach(() => {
    currentRequest = {
      deletion_request_id: 'del-1',
      tenant_id: 'default-tenant',
      user_id: 'user-1',
      status: 'KEY_DESTROYED', // valid starting point for advanceRequest(..., 'CASCADE_PENDING', ...)
      created_at: new Date(),
      status_history: [],
      janitor_wipes: [],
    };

    mockDeletionRequestRepo = {
      createDeletionRequest: jest.fn(),
      getActiveDeletionRequestForUser: jest.fn(),
      updateJanitorWipeStatus: jest.fn().mockResolvedValue(undefined),
      // Stateful: getDeletionRequest reflects whatever the last
      // updateDeletionRequestStatus call persisted, matching how the real
      // Firestore-backed repo behaves. Without this, every recursive
      // advanceRequest() call (e.g. CASCADE_COMPLETE -> CERTIFICATE_ISSUED)
      // would re-read the stale original status and fail its own transition
      // check.
      getDeletionRequest: jest.fn(async () => ({ ...currentRequest })),
      updateDeletionRequestStatus: jest.fn(async (_id: string, newStatus: DeletionRequestStatus, updateFields: any) => {
        currentRequest = { ...currentRequest, ...updateFields, status: newStatus };
      }),
    } as any;
    mockFirestoreRegistry = { shredKeyForUser: jest.fn().mockResolvedValue(undefined) } as any;
    mockLineageRepository = { recordEvent: jest.fn().mockResolvedValue(undefined) } as any;
    mockJanitorService = {
      // Non-empty by default: an empty plan takes the CASCADE_PENDING
      // short-circuit straight to CASCADE_COMPLETE, which isn't what these
      // tests are exercising (they care about processCleanup's outcome).
      createCleanupPlan: jest.fn().mockResolvedValue([
        { userId: 'user-1', destination: 'hubspot', status: 'PENDING', attempts: 0 },
        { userId: 'user-1', destination: 'salesforce', status: 'PENDING', attempts: 0 },
      ]),
      processCleanup: jest.fn(),
    } as any;
    mockDekKmsClient = {} as any;
    mockCertificateService = {
      issueAndStoreCertificate: jest.fn().mockResolvedValue({ gcsPath: 'gs://certs/del-1.json' }),
    } as any;

    service = new DeletionRequestService(
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepository as unknown as BigQueryLineageRepository,
      mockJanitorService as unknown as JanitorService,
      mockDekKmsClient as unknown as CloudKMSClient,
      mockCertificateService as unknown as CertificateService,
    );
  });

  async function flushMicrotasks(times = 15): Promise<void> {
    for (let i = 0; i < times; i++) {
      await new Promise(resolve => setImmediate(resolve));
    }
  }

  it('withholds the certificate and lands on CASCADE_PARTIAL_FAILURE when a SaaS wipe fails', async () => {
    mockJanitorService.processCleanup.mockResolvedValue([
      { userId: 'user-1', destination: 'hubspot', status: 'COMPLETE', attempts: 1 },
      { userId: 'user-1', destination: 'salesforce', status: 'FAILED', attempts: 3 },
    ]);

    await service.advanceRequest('del-1', 'CASCADE_PENDING', 'op-1');
    await flushMicrotasks();

    expect(mockDeletionRequestRepo.updateJanitorWipeStatus).toHaveBeenCalledWith(
      'del-1', 'hubspot', 'SUCCEEDED', { attempts: 1 }
    );
    expect(mockDeletionRequestRepo.updateJanitorWipeStatus).toHaveBeenCalledWith(
      'del-1', 'salesforce', 'FAILED', { attempts: 3 }
    );

    expect(currentRequest.status).toBe('CASCADE_PARTIAL_FAILURE');
    expect(mockDeletionRequestRepo.updateDeletionRequestStatus).not.toHaveBeenCalledWith(
      'del-1', 'CERTIFICATE_ISSUED', expect.anything()
    );
    expect(mockCertificateService.issueAndStoreCertificate).not.toHaveBeenCalled();
  });

  it('still reaches CERTIFICATE_ISSUED when every SaaS wipe succeeds', async () => {
    mockJanitorService.processCleanup.mockResolvedValue([
      { userId: 'user-1', destination: 'hubspot', status: 'COMPLETE', attempts: 1 },
      { userId: 'user-1', destination: 'salesforce', status: 'COMPLETE', attempts: 1 },
    ]);

    await service.advanceRequest('del-1', 'CASCADE_PENDING', 'op-1');
    await flushMicrotasks();

    expect(mockDeletionRequestRepo.updateJanitorWipeStatus).toHaveBeenCalledWith(
      'del-1', 'hubspot', 'SUCCEEDED', { attempts: 1 }
    );
    expect(mockDeletionRequestRepo.updateJanitorWipeStatus).toHaveBeenCalledWith(
      'del-1', 'salesforce', 'SUCCEEDED', { attempts: 1 }
    );

    expect(currentRequest.status).toBe('CERTIFICATE_ISSUED');
    expect(mockCertificateService.issueAndStoreCertificate).toHaveBeenCalledWith('user-1', 'del-1', 'default-tenant');
  });
});
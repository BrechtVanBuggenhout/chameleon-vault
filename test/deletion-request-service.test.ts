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

describe('DeletionRequestService - createRequest actor attribution', () => {
  let service: DeletionRequestService;
  let mockDeletionRequestRepo: jest.Mocked<DeletionRequestRepository>;
  let mockFirestoreRegistry: jest.Mocked<FirestoreRegistry>;
  let mockLineageRepository: jest.Mocked<BigQueryLineageRepository>;
  let mockJanitorService: jest.Mocked<JanitorService>;
  let mockDekKmsClient: jest.Mocked<CloudKMSClient>;
  let mockCertificateService: jest.Mocked<CertificateService>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockDeletionRequestRepo = new (DeletionRequestRepository as jest.Mock)();
    mockFirestoreRegistry = new (FirestoreRegistry as jest.Mock)();
    mockLineageRepository = new (BigQueryLineageRepository as jest.Mock)();
    mockJanitorService = new (JanitorService as jest.Mock)();
    mockDekKmsClient = new (CloudKMSClient as jest.Mock)();
    mockCertificateService = new (CertificateService as jest.Mock)();
    mockDeletionRequestRepo.getActiveDeletionRequestForUser = jest.fn().mockResolvedValue(null) as never;
    mockDeletionRequestRepo.createDeletionRequest = jest.fn().mockResolvedValue({
      deletion_request_id: 'op-1',
      tenant_id: 'acme',
      user_id: 'user-1',
      status: 'SHRED_REQUESTED',
      created_at: new Date(),
      status_history: [],
      janitor_wipes: [],
    }) as never;
    mockLineageRepository.recordEvent = jest.fn().mockResolvedValue(undefined) as never;

    service = new DeletionRequestService(
      mockDeletionRequestRepo, mockFirestoreRegistry, mockLineageRepository, mockJanitorService, mockDekKmsClient, mockCertificateService
    );
  });

  it('passes the resolved actor email through to the repository', async () => {
    const result = await service.createRequest('user-1', 'op-1', 'acme', 'analyst@example.com');
    expect(mockDeletionRequestRepo.createDeletionRequest).toHaveBeenCalledWith('user-1', 'op-1', 'acme', 'analyst@example.com');
    expect(result.alreadyExisted).toBe(false);
  });

  it('passes undefined through when no actor was resolved (shared-key caller)', async () => {
    const result = await service.createRequest('user-1', 'op-1', 'acme');
    expect(mockDeletionRequestRepo.createDeletionRequest).toHaveBeenCalledWith('user-1', 'op-1', 'acme', undefined);
    expect(result.alreadyExisted).toBe(false);
  });

  it('flags alreadyExisted and skips creating a new request when one is already active', async () => {
    const existing: DeletionRequest = {
      deletion_request_id: 'del-existing',
      tenant_id: 'acme',
      user_id: 'user-1',
      status: 'CASCADE_PARTIAL_FAILURE',
      created_at: new Date(),
      status_history: [],
      janitor_wipes: [],
    };
    mockDeletionRequestRepo.getActiveDeletionRequestForUser = jest.fn().mockResolvedValue(existing) as never;

    const result = await service.createRequest('user-1', 'op-2', 'acme');

    expect(result.alreadyExisted).toBe(true);
    expect(result.request).toEqual(existing);
    expect(mockDeletionRequestRepo.createDeletionRequest).not.toHaveBeenCalled();
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

  it('force-recovers into CASCADE_PARTIAL_FAILURE, never a silent stall, when certificate issuance throws after CASCADE_COMPLETE', async () => {
    // Every SaaS wipe succeeds, so the cascade reaches CASCADE_COMPLETE and
    // recurses into CERTIFICATE_ISSUED for real -- but certificate issuance
    // itself throws. Before this fix, that exception would only be logged,
    // leaving the request sitting at CASCADE_COMPLETE forever with no
    // visible error and no certificate.
    mockJanitorService.processCleanup.mockResolvedValue([
      { userId: 'user-1', destination: 'hubspot', status: 'COMPLETE', attempts: 1 },
    ]);
    mockCertificateService.issueAndStoreCertificate.mockRejectedValue(new Error('KMS signing key unavailable'));

    await service.advanceRequest('del-1', 'CASCADE_PENDING', 'op-1');
    await flushMicrotasks();

    expect(currentRequest.status).toBe('CASCADE_PARTIAL_FAILURE');
    // failedDestinations is recorded via the lineage event (existing
    // behavior for this transition), not persisted onto the request
    // document itself -- confirm the internal error made it into that trail
    // rather than only a server log line.
    expect(mockLineageRepository.recordEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'CASCADE_PARTIAL_FAILURE',
        context: {
          failedDestinations: expect.arrayContaining([expect.stringContaining('KMS signing key unavailable')]),
        },
      })
    );
  });
});

describe('DeletionRequestService - CASCADE_IN_PROGRESS retries a stuck CASCADE_PARTIAL_FAILURE', () => {
  // Same manual-mock-class pattern as the suite above (automock doesn't
  // wrap async prototype methods under this project's ts-jest ESM preset).
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
      status: 'CASCADE_PARTIAL_FAILURE', // starting point for the retry
      created_at: new Date(),
      status_history: [],
      janitor_wipes: [
        { destination: 'hubspot', status: 'SUCCEEDED', updated_at: new Date() },
        { destination: 'salesforce', status: 'FAILED', updated_at: new Date(), details: { error: 'timeout' } },
      ],
    };

    mockDeletionRequestRepo = {
      createDeletionRequest: jest.fn(),
      getActiveDeletionRequestForUser: jest.fn(),
      updateJanitorWipeStatus: jest.fn().mockResolvedValue(undefined),
      getDeletionRequest: jest.fn(async () => ({ ...currentRequest })),
      updateDeletionRequestStatus: jest.fn(async (_id: string, newStatus: DeletionRequestStatus, updateFields: any) => {
        currentRequest = { ...currentRequest, ...updateFields, status: newStatus };
      }),
    } as any;
    mockFirestoreRegistry = { shredKeyForUser: jest.fn().mockResolvedValue(undefined) } as any;
    mockLineageRepository = { recordEvent: jest.fn().mockResolvedValue(undefined) } as any;
    mockJanitorService = {
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

  it('re-runs the cleanup loop and reaches CERTIFICATE_ISSUED when the retry succeeds', async () => {
    mockJanitorService.processCleanup.mockResolvedValue([
      { userId: 'user-1', destination: 'hubspot', status: 'COMPLETE', attempts: 1 },
      { userId: 'user-1', destination: 'salesforce', status: 'COMPLETE', attempts: 2 },
    ]);

    await service.advanceRequest('del-1', 'CASCADE_IN_PROGRESS', 'op-2');
    await flushMicrotasks();

    expect(mockJanitorService.processCleanup).toHaveBeenCalledWith('user-1', 'default-tenant');
    expect(mockDeletionRequestRepo.updateJanitorWipeStatus).toHaveBeenCalledWith(
      'del-1', 'salesforce', 'SUCCEEDED', { attempts: 2, recordsFound: undefined }
    );
    expect(currentRequest.status).toBe('CERTIFICATE_ISSUED');
    expect(mockCertificateService.issueAndStoreCertificate).toHaveBeenCalledWith('user-1', 'del-1', 'default-tenant');
  });

  it('lands back on CASCADE_PARTIAL_FAILURE, not stuck at CASCADE_IN_PROGRESS, when the retry fails again', async () => {
    mockJanitorService.processCleanup.mockResolvedValue([
      { userId: 'user-1', destination: 'hubspot', status: 'COMPLETE', attempts: 1 },
      { userId: 'user-1', destination: 'salesforce', status: 'FAILED', attempts: 5 },
    ]);

    await service.advanceRequest('del-1', 'CASCADE_IN_PROGRESS', 'op-2');
    await flushMicrotasks();

    expect(currentRequest.status).toBe('CASCADE_PARTIAL_FAILURE');
    expect(mockCertificateService.issueAndStoreCertificate).not.toHaveBeenCalled();
  });

  it('is a genuinely valid transition, not silently rejected, from CASCADE_PARTIAL_FAILURE', async () => {
    mockJanitorService.processCleanup.mockResolvedValue([
      { userId: 'user-1', destination: 'hubspot', status: 'COMPLETE', attempts: 1 },
      { userId: 'user-1', destination: 'salesforce', status: 'COMPLETE', attempts: 1 },
    ]);

    // Before this fix, CASCADE_IN_PROGRESS had no case in the switch at all
    // -- the status field would flip with zero real retry behavior. This
    // asserts the retry actually did something, not just that the call
    // didn't throw.
    await service.advanceRequest('del-1', 'CASCADE_IN_PROGRESS', 'op-2');
    await flushMicrotasks();

    expect(mockJanitorService.createCleanupPlan).toHaveBeenCalledWith('user-1', 'default-tenant');
    expect(mockLineageRepository.recordEvent).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'CASCADE_RETRY_TRIGGERED' })
    );
  });
});

describe('DeletionRequestService - source redaction integration', () => {
  let service: DeletionRequestService;
  let mockDeletionRequestRepo: { [K in keyof DeletionRequestRepository]: jest.Mock };
  let mockFirestoreRegistry: { [K in keyof FirestoreRegistry]: jest.Mock };
  let mockLineageRepository: { [K in keyof BigQueryLineageRepository]: jest.Mock };
  let mockJanitorService: { [K in keyof JanitorService]: jest.Mock };
  let mockDekKmsClient: { [K in keyof CloudKMSClient]: jest.Mock };
  let mockCertificateService: { [K in keyof CertificateService]: jest.Mock };
  let mockSourceRedactionService: { planRedaction: jest.Mock; redactUserInDeclaredSources: jest.Mock };
  let currentRequest: DeletionRequest;

  beforeEach(() => {
    currentRequest = {
      deletion_request_id: 'del-1',
      tenant_id: 'default-tenant',
      user_id: 'user-1',
      status: 'KEY_DESTROYED',
      created_at: new Date(),
      status_history: [],
      janitor_wipes: [],
    };

    mockDeletionRequestRepo = {
      createDeletionRequest: jest.fn(),
      getActiveDeletionRequestForUser: jest.fn(),
      updateJanitorWipeStatus: jest.fn().mockResolvedValue(undefined),
      getDeletionRequest: jest.fn(async () => ({ ...currentRequest })),
      updateDeletionRequestStatus: jest.fn(async (_id: string, newStatus: DeletionRequestStatus, updateFields: any) => {
        currentRequest = { ...currentRequest, ...updateFields, status: newStatus };
      }),
    } as any;
    mockFirestoreRegistry = { shredKeyForUser: jest.fn().mockResolvedValue(undefined) } as any;
    mockLineageRepository = { recordEvent: jest.fn().mockResolvedValue(undefined) } as any;
    // No SaaS tasks in this suite -- isolates source redaction's own effect
    // on the shortcut logic and the certificate gate.
    mockJanitorService = {
      createCleanupPlan: jest.fn().mockResolvedValue([]),
      processCleanup: jest.fn().mockResolvedValue([]),
    } as any;
    mockDekKmsClient = {} as any;
    mockCertificateService = {
      issueAndStoreCertificate: jest.fn().mockResolvedValue({ gcsPath: 'gs://certs/del-1.json' }),
    } as any;
    mockSourceRedactionService = {
      planRedaction: jest.fn().mockReturnValue([]),
      redactUserInDeclaredSources: jest.fn().mockResolvedValue([]),
    };

    service = new DeletionRequestService(
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepository as unknown as BigQueryLineageRepository,
      mockJanitorService as unknown as JanitorService,
      mockDekKmsClient as unknown as CloudKMSClient,
      mockCertificateService as unknown as CertificateService,
      mockSourceRedactionService as any
    );
  });

  async function flushMicrotasks(times = 15): Promise<void> {
    for (let i = 0; i < times; i++) {
      await new Promise(resolve => setImmediate(resolve));
    }
  }

  it('does not shortcut to CASCADE_COMPLETE when there are no SaaS tasks but there is a pending redaction resource', async () => {
    mockSourceRedactionService.planRedaction.mockReturnValue([{ resourceId: 'bigquery:acme.crm.contacts' }]);
    mockSourceRedactionService.redactUserInDeclaredSources.mockResolvedValue([
      { resourceId: 'bigquery:acme.crm.contacts', success: true, rowsAffected: 1 },
    ]);

    await service.advanceRequest('del-1', 'CASCADE_PENDING', 'op-1');
    await flushMicrotasks();

    // Reached CASCADE_PENDING for real (not the empty-plan shortcut), and
    // the redaction actually ran.
    expect(mockSourceRedactionService.redactUserInDeclaredSources).toHaveBeenCalledWith('user-1', 'default-tenant');
    expect(currentRequest.status).toBe('CERTIFICATE_ISSUED');
  });

  it('withholds the certificate when a source redaction fails, even if there are no SaaS tasks at all', async () => {
    mockSourceRedactionService.planRedaction.mockReturnValue([{ resourceId: 'bigquery:acme.crm.contacts' }]);
    mockSourceRedactionService.redactUserInDeclaredSources.mockResolvedValue([
      { resourceId: 'bigquery:acme.crm.contacts', success: false, error: 'permission denied' },
    ]);

    await service.advanceRequest('del-1', 'CASCADE_PENDING', 'op-1');
    await flushMicrotasks();

    expect(mockDeletionRequestRepo.updateJanitorWipeStatus).toHaveBeenCalledWith(
      'del-1', 'bigquery:acme.crm.contacts', 'FAILED', { rowsAffected: undefined, error: 'permission denied' }
    );
    expect(currentRequest.status).toBe('CASCADE_PARTIAL_FAILURE');
    expect(mockCertificateService.issueAndStoreCertificate).not.toHaveBeenCalled();
  });

  it('reaches CERTIFICATE_ISSUED and records the resourceId as a destination when redaction succeeds', async () => {
    mockSourceRedactionService.planRedaction.mockReturnValue([{ resourceId: 'bigquery:acme.crm.contacts' }]);
    mockSourceRedactionService.redactUserInDeclaredSources.mockResolvedValue([
      { resourceId: 'bigquery:acme.crm.contacts', success: true, rowsAffected: 1 },
    ]);

    await service.advanceRequest('del-1', 'CASCADE_PENDING', 'op-1');
    await flushMicrotasks();

    expect(mockDeletionRequestRepo.updateJanitorWipeStatus).toHaveBeenCalledWith(
      'del-1', 'bigquery:acme.crm.contacts', 'SUCCEEDED', { rowsAffected: 1, error: undefined }
    );
    expect(currentRequest.status).toBe('CERTIFICATE_ISSUED');
    expect(mockCertificateService.issueAndStoreCertificate).toHaveBeenCalledWith('user-1', 'del-1', 'default-tenant');
  });

  it('is a no-op when sourceRedactionService is not provided at all (backward compatible)', async () => {
    const serviceWithoutRedaction = new DeletionRequestService(
      mockDeletionRequestRepo as unknown as DeletionRequestRepository,
      mockFirestoreRegistry as unknown as FirestoreRegistry,
      mockLineageRepository as unknown as BigQueryLineageRepository,
      mockJanitorService as unknown as JanitorService,
      mockDekKmsClient as unknown as CloudKMSClient,
      mockCertificateService as unknown as CertificateService
      // sourceRedactionService omitted entirely
    );

    await serviceWithoutRedaction.advanceRequest('del-1', 'CASCADE_PENDING', 'op-1');
    await flushMicrotasks();

    // No SaaS tasks, no redaction service configured -> the original empty-
    // plan shortcut still applies, reaching CERTIFICATE_ISSUED immediately.
    expect(currentRequest.status).toBe('CERTIFICATE_ISSUED');
  });
});
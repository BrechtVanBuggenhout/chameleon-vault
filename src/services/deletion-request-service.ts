import { DeletionRequest, DeletionRequestStatus } from '../types/deletion-request.js';
import { DeletionRequestRepository } from '../gcp/deletion-request-repository.js';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../gcp/bigquery-lineage.js';
import { JanitorService } from './janitor.js';
import { createLogger } from '../logging/index.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import { CertificateService } from './certificate-service.js';

const logger = createLogger('deletion-request-service');

export class DeletionRequestService {
  constructor(
    private readonly deletionRequestRepo: DeletionRequestRepository,
    private readonly firestoreRegistry: FirestoreRegistry,
    private readonly lineageRepo: BigQueryLineageRepository,
    private readonly janitorService: JanitorService,
    private readonly kmsClient: CloudKMSClient,
    private readonly certificateService: CertificateService
  ) {}

  async createRequest(userId: string, operationId: string, tenantId: string = 'default-tenant'): Promise<DeletionRequest> {
    // Check for existing active deletion request for the user
    const existingRequest = await this.deletionRequestRepo.getActiveDeletionRequestForUser(userId, tenantId);
    if (existingRequest) {
      logger.warn({ userId, existingRequestId: existingRequest.deletion_request_id }, 'Active deletion request already exists for user');
      return existingRequest; // Return existing request for idempotency
    }

    const deletionRequest = await this.deletionRequestRepo.createDeletionRequest(userId, operationId, tenantId);
    // RECOMMENDATION: Move to Cloud Logging Sinks. 
    // Instead of calling BQ API, log a structured JSON object to stdout.
    // GCP Log Sinks will then transport this to BigQuery asynchronously without impacting app latency.
    await this.lineageRepo.recordEvent({
      operationId,
      deletionRequestId: operationId,
      userId,
      tenantId,
      eventType: 'SHRED_REQUESTED',
      source: 'key-vault',
      destination: 'deletion-request-log',
      context: { status: 'SHRED_REQUESTED' },
    }).catch(err => logger.error({ err, userId }, 'Background lineage logging failed (SHRED_REQUESTED)'));
    return deletionRequest;
  }

  async getRequest(deletionRequestId: string): Promise<DeletionRequest | null> {
    return this.deletionRequestRepo.getDeletionRequest(deletionRequestId);
  }

  async advanceRequest(
    deletionRequestId: string,
    newStatus: DeletionRequestStatus,
    operationId: string,
    context?: { failedDestinations?: string[] }
  ): Promise<DeletionRequest> {
    const request = await this.deletionRequestRepo.getDeletionRequest(deletionRequestId);
    if (!request) {
      logger.error({ deletionRequestId }, 'Advancement failed: Request not found');
      throw new Error(`Deletion request ${deletionRequestId} not found`);
    }

    // Validate state transition (simplified for brevity)
    if (!this.isValidTransition(request.status, newStatus)) {
      throw new Error(`Invalid state transition from ${request.status} to ${newStatus}`);
    }

    const tenantId = request.tenant_id || 'default-tenant';

    logger.info({ userId: request.user_id, tenantId, from: request.status, to: newStatus }, 'Advancing deletion request state');
    const updateFields: Partial<DeletionRequest> = {};
    let afterStatusPersisted: (() => void) | undefined;

    switch (newStatus) {
      case 'KEY_DESTROYED':
        // Perform irreversible key destruction
        await this.firestoreRegistry.shredKeyForUser(request.user_id, tenantId, deletionRequestId);
        updateFields.key_destroyed_at = new Date();
        await this.lineageRepo.recordEvent({
          operationId,
          deletionRequestId,
          userId: request.user_id,
          tenantId,
          eventType: 'KEY_SHREDDED',
          source: 'key-vault',
          destination: 'key-registry',
          context: { status: 'KEY_SHREDDED', deletion_request_id: deletionRequestId, user_id: request.user_id },
        }).catch(err => logger.error({ err, userId: request.user_id }, 'Background lineage logging failed (KEY_DESTROYED)'));
        break;
      case 'CASCADE_PENDING':
        const tasks = await this.janitorService.createCleanupPlan(request.user_id, tenantId);
        
        if (tasks.length === 0) {
          logger.info({ userId: request.user_id }, 'No SaaS tasks found, advancing to complete');
          // If no SaaS cleanup is needed, move straight to COMPLETE
          return this.advanceRequest(deletionRequestId, 'CASCADE_COMPLETE', operationId);
        }

        // Trigger the cleanup loop (SaaS wipes) after the
        // CASCADE_PENDING state is persisted, otherwise fast connectors can race
        // the state machine into an invalid transition.
        afterStatusPersisted = () => {
          this.janitorService.processCleanup(request.user_id, tenantId).then(async (results) => {
            // Record each destination's real outcome on the request itself
            // (janitor_wipes), not just as a lineage event -- this is what
            // the next step actually gates on. processCleanup() already
            // retries and DLQs permanent failures; the point here is to
            // stop pretending nothing failed once it returns.
            for (const result of results) {
              await this.updateJanitorWipeStatus(
                deletionRequestId,
                result.destination,
                result.status === 'COMPLETE' ? 'SUCCEEDED' : 'FAILED',
                { attempts: result.attempts, recordsFound: result.recordsFound }
              ).catch(err => logger.error({ err, destination: result.destination }, 'Failed to record janitor wipe status'));
            }

            const failed = results.filter(r => r.status !== 'COMPLETE');
            const nextStatus: DeletionRequestStatus = failed.length > 0 ? 'CASCADE_PARTIAL_FAILURE' : 'CASCADE_COMPLETE';
            await this.advanceRequest(deletionRequestId, nextStatus, operationId, {
              failedDestinations: failed.map(r => r.destination),
            });
          }).catch(err =>
            logger.error({ err, userId: request.user_id }, 'Janitor cleanup loop failed')
          );
        };

        logger.info({ deletionRequestId, userId: request.user_id }, 'Janitor cascade triggered for user');

        updateFields.cascade_initiated_at = new Date();
        await this.lineageRepo.recordEvent({
          operationId,
          deletionRequestId,
          userId: request.user_id,
          tenantId,
          eventType: 'JANITOR_TRIGGERED',
          source: 'key-vault',
          destination: 'janitor-service',
          context: { destinations: tasks.map(t => t.destination) },
        }).catch(err => logger.error({ err, userId: request.user_id }, 'Background lineage logging failed (JANITOR_TRIGGERED)'));
        break;
      case 'CASCADE_COMPLETE':
        // When cascade is done, automatically move to certificate issuance
        await this.deletionRequestRepo.updateDeletionRequestStatus(deletionRequestId, newStatus, updateFields);
        return this.advanceRequest(deletionRequestId, 'CERTIFICATE_ISSUED', operationId);

      case 'CASCADE_PARTIAL_FAILURE':
        // Deliberately does NOT cascade into CERTIFICATE_ISSUED, unlike
        // CASCADE_COMPLETE above -- this is the whole point of this state.
        // A signed Certificate of Destruction must never be issued while a
        // destination is known to still hold the user's data.
        logger.error(
          { deletionRequestId, userId: request.user_id, failedDestinations: context?.failedDestinations },
          'Cascade wipe did not reach every destination -- certificate withheld'
        );
        await this.lineageRepo.recordEvent({
          operationId,
          deletionRequestId,
          userId: request.user_id,
          tenantId,
          eventType: 'CASCADE_PARTIAL_FAILURE',
          source: 'key-vault',
          destination: 'janitor-service',
          context: { failedDestinations: context?.failedDestinations ?? [] },
        }).catch(err => logger.error({ err, userId: request.user_id }, 'Background lineage logging failed (CASCADE_PARTIAL_FAILURE)'));
        break;

      case 'CERTIFICATE_ISSUED':
        // Generate and store the certificate in GCS as required by infra
        const { gcsPath } = await this.certificateService.issueAndStoreCertificate(request.user_id, request.deletion_request_id, tenantId);
        
        updateFields.certificate_issued_at = new Date();
        // Lets GET /certificate/:userId return the exact stored (chained)
        // certificate instead of re-signing a fresh one on every call.
        updateFields.certificate_gcs_path = gcsPath;
        await this.lineageRepo.recordEvent({
          operationId,
          deletionRequestId,
          userId: request.user_id,
          tenantId,
          eventType: 'CERTIFICATE_ISSUED',
          source: 'key-vault',
          destination: 'certificate-service',
          context: { certificate_gcs_path: gcsPath },
        }).catch(err => logger.error({ err, userId: request.user_id }, 'Background lineage logging failed (CERTIFICATE_ISSUED)'));
        break;
      // Other states would have their own logic
    }

    await this.deletionRequestRepo.updateDeletionRequestStatus(deletionRequestId, newStatus, updateFields);
    afterStatusPersisted?.();
    return { ...request, ...updateFields, status: newStatus };
  }

  async updateJanitorWipeStatus(
    deletionRequestId: string,
    destination: string,
    status: 'PENDING' | 'IN_PROGRESS' | 'SUCCEEDED' | 'FAILED' | 'DLQ',
    details: any
  ): Promise<void> {
    await this.deletionRequestRepo.updateJanitorWipeStatus(
      deletionRequestId,
      destination,
      status,
      details
    );
  }

  private isValidTransition(currentStatus: DeletionRequestStatus, newStatus: DeletionRequestStatus): boolean {
    // Note: Shortcuts (e.g., KEY_DESTROYED -> CASCADE_COMPLETE) are allowed 
    // when no downstream SaaS tasks are found.
    const transitions: Record<DeletionRequestStatus, DeletionRequestStatus[]> = {
      'SHRED_REQUESTED': ['KEY_DESTROYED', 'CASCADE_PARTIAL_FAILURE'],
      'KEY_DESTROYED': ['CASCADE_PENDING', 'CASCADE_COMPLETE', 'CERTIFICATE_ISSUED', 'CASCADE_PARTIAL_FAILURE'],
      'CASCADE_PENDING': ['CASCADE_IN_PROGRESS', 'CASCADE_COMPLETE', 'CASCADE_PARTIAL_FAILURE'],
      'CASCADE_IN_PROGRESS': ['CASCADE_COMPLETE', 'CASCADE_PARTIAL_FAILURE'],
      'CASCADE_PARTIAL_FAILURE': ['CASCADE_IN_PROGRESS', 'SHRED_REQUESTED'],
      'CASCADE_COMPLETE': ['CERTIFICATE_ISSUED', 'CASCADE_PARTIAL_FAILURE'],
      'CERTIFICATE_ISSUED': [] // Terminal state
    };

    const allowed = transitions[currentStatus] || [];
    const isValid = allowed.includes(newStatus);

    if (!isValid) {
      logger.warn({ currentStatus, newStatus }, 'Rejected invalid state transition');
    }

    return isValid;
  }
}

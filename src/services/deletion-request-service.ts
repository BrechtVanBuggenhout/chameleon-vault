import { DeletionRequest, DeletionRequestStatus } from '../types/deletion-request.js';
import { DeletionRequestRepository } from '../gcp/deletion-request-repository.js';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../gcp/bigquery-lineage.js';
import { JanitorService } from './janitor.js';
import { SourceRedactionService } from './source-redaction-service.js';
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
    private readonly certificateService: CertificateService,
    // Optional: undefined means no manually-declared resource has ever
    // opted into REDACT_IN_PLACE, so this step is skippable entirely rather
    // than requiring every caller (including existing tests) to wire up a
    // BigQuery client just for a feature they don't use.
    private readonly sourceRedactionService?: SourceRedactionService
  ) {}

  async createRequest(
    userId: string,
    operationId: string,
    tenantId: string = 'default-tenant',
    requestedBy?: string
  ): Promise<{ request: DeletionRequest; alreadyExisted: boolean }> {
    // Check for existing active deletion request for the user
    const existingRequest = await this.deletionRequestRepo.getActiveDeletionRequestForUser(userId, tenantId);
    if (existingRequest) {
      logger.warn({ userId, existingRequestId: existingRequest.deletion_request_id }, 'Active deletion request already exists for user');
      // Idempotency: hand back the existing request rather than erroring --
      // but callers MUST check alreadyExisted before blindly advancing it
      // (e.g. straight to KEY_DESTROYED), since it may already be well past
      // that point, or stuck in CASCADE_PARTIAL_FAILURE needing a real retry
      // (CASCADE_IN_PROGRESS) rather than a from-scratch advance.
      return { request: existingRequest, alreadyExisted: true };
    }

    const deletionRequest = await this.deletionRequestRepo.createDeletionRequest(userId, operationId, tenantId, requestedBy);
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
    return { request: deletionRequest, alreadyExisted: false };
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
      case 'CASCADE_PENDING': {
        const plan = await this.prepareCascadeTrigger(deletionRequestId, request, tenantId, operationId);
        if (plan.shortcutToComplete) {
          logger.info({ userId: request.user_id }, 'No SaaS tasks or source redactions found, advancing to complete');
          // If no SaaS cleanup or source redaction is needed, move straight to COMPLETE
          return this.advanceRequest(deletionRequestId, 'CASCADE_COMPLETE', operationId);
        }

        afterStatusPersisted = plan.afterStatusPersisted;
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
          context: { destinations: plan.taskDestinations },
        }).catch(err => logger.error({ err, userId: request.user_id }, 'Background lineage logging failed (JANITOR_TRIGGERED)'));
        break;
      }
      case 'CASCADE_IN_PROGRESS': {
        // Retry path from CASCADE_PARTIAL_FAILURE. Before this, the
        // transition table advertised this as valid but nothing here ever
        // handled it -- advancing into CASCADE_IN_PROGRESS just flipped the
        // status field with no real retry, leaving the request permanently
        // stuck with no certificate and no way to actually fix it (found via
        // a real customer report 2026-08-16). Re-runs the exact same
        // cleanup loop CASCADE_PENDING triggers -- simple and correct: wipe
        // operations are idempotent, so re-attempting an already-succeeded
        // destination is harmless, and this reuses one code path instead of
        // maintaining "retry failed-only" logic that isn't needed yet.
        const plan = await this.prepareCascadeTrigger(deletionRequestId, request, tenantId, operationId);
        if (plan.shortcutToComplete) {
          logger.info({ userId: request.user_id }, 'Cascade retry found nothing left to wipe, advancing to complete');
          return this.advanceRequest(deletionRequestId, 'CASCADE_COMPLETE', operationId);
        }

        afterStatusPersisted = plan.afterStatusPersisted;
        logger.info({ deletionRequestId, userId: request.user_id }, 'Cascade retry triggered for user');

        updateFields.cascade_initiated_at = new Date();
        await this.lineageRepo.recordEvent({
          operationId,
          deletionRequestId,
          userId: request.user_id,
          tenantId,
          eventType: 'CASCADE_RETRY_TRIGGERED',
          source: 'key-vault',
          destination: 'janitor-service',
          context: { destinations: plan.taskDestinations },
        }).catch(err => logger.error({ err, userId: request.user_id }, 'Background lineage logging failed (CASCADE_RETRY_TRIGGERED)'));
        break;
      }
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

  /**
   * Shared by CASCADE_PENDING (first attempt) and CASCADE_IN_PROGRESS
   * (retry after CASCADE_PARTIAL_FAILURE) -- builds the cleanup plan and, if
   * there's real work to do, the closure that runs the janitor + source
   * redaction loop and records each destination's outcome. Kept as one path
   * so a retry can never drift from what a first attempt actually does.
   */
  private async prepareCascadeTrigger(
    deletionRequestId: string,
    request: DeletionRequest,
    tenantId: string,
    operationId: string
  ): Promise<{ shortcutToComplete: true } | { shortcutToComplete: false; afterStatusPersisted: () => void; taskDestinations: string[] }> {
    const tasks = await this.janitorService.createCleanupPlan(request.user_id, tenantId);
    const redactionResources = this.sourceRedactionService?.planRedaction(tenantId) ?? [];

    if (tasks.length === 0 && redactionResources.length === 0) {
      return { shortcutToComplete: true };
    }

    const afterStatusPersisted = () => {
      Promise.all([
        this.janitorService.processCleanup(request.user_id, tenantId),
        redactionResources.length > 0 && this.sourceRedactionService
          ? this.sourceRedactionService.redactUserInDeclaredSources(request.user_id, tenantId)
          : Promise.resolve([]),
      ]).then(async ([janitorResults, redactionResults]) => {
        // Record each destination's real outcome on the request itself
        // (janitor_wipes), not just as a lineage event -- this is what
        // the next step actually gates on. processCleanup() already
        // retries and DLQs permanent failures; the point here is to
        // stop pretending nothing failed once it returns.
        for (const result of janitorResults) {
          await this.updateJanitorWipeStatus(
            deletionRequestId,
            result.destination,
            result.status === 'COMPLETE' ? 'SUCCEEDED' : 'FAILED',
            { attempts: result.attempts, recordsFound: result.recordsFound }
          ).catch(err => logger.error({ err, destination: result.destination }, 'Failed to record janitor wipe status'));
        }
        // Source-redaction resources are tracked the same way, using
        // the resource id as the destination label -- a redaction
        // failure withholds the certificate exactly like a SaaS wipe
        // failure already does, since both mean the user's data
        // demonstrably still exists somewhere Chameleon knows about.
        for (const result of redactionResults) {
          await this.updateJanitorWipeStatus(
            deletionRequestId,
            result.resourceId,
            result.success ? 'SUCCEEDED' : 'FAILED',
            { rowsAffected: result.rowsAffected, error: result.error }
          ).catch(err => logger.error({ err, destination: result.resourceId }, 'Failed to record source redaction status'));
        }

        const failedJanitor = janitorResults.filter(r => r.status !== 'COMPLETE');
        const failedRedaction = redactionResults.filter(r => !r.success);
        const nextStatus: DeletionRequestStatus =
          failedJanitor.length > 0 || failedRedaction.length > 0 ? 'CASCADE_PARTIAL_FAILURE' : 'CASCADE_COMPLETE';
        await this.advanceRequest(deletionRequestId, nextStatus, operationId, {
          failedDestinations: [...failedJanitor.map(r => r.destination), ...failedRedaction.map(r => r.resourceId)],
        });
      }).catch(async (err) => {
        logger.error({ err, userId: request.user_id }, 'Janitor cleanup / source redaction loop failed');
        // This only fires for a throw *inside* the .then() above --
        // janitorService.processCleanup and
        // sourceRedactionService.redactUserInDeclaredSources both catch
        // internally and never reject the Promise.all itself. The most
        // likely case is CASCADE_COMPLETE's own recursive advanceRequest
        // into CERTIFICATE_ISSUED throwing (e.g. certificate issuance
        // failing) -- CASCADE_COMPLETE has already been persisted by
        // then, so the request would otherwise sit there silently,
        // looking "done" with no certificate and no visible error.
        // Force a terminal, visible failure state instead of only
        // logging, so this never becomes another silent stall.
        try {
          await this.advanceRequest(deletionRequestId, 'CASCADE_PARTIAL_FAILURE', operationId, {
            failedDestinations: [`internal-error: ${err instanceof Error ? err.message : String(err)}`],
          });
        } catch (recoveryErr) {
          logger.error(
            { recoveryErr, deletionRequestId },
            'Failed to force deletion request into a visible failure state after cascade error'
          );
        }
      });
    };

    return { shortcutToComplete: false, afterStatusPersisted, taskDestinations: tasks.map(t => t.destination) };
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

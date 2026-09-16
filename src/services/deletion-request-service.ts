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

    // Atomically claims this exact transition (status only) before running
    // a handler with a side effect that must not fire twice -- e.g. two
    // concurrent advanceRequest(..., 'CERTIFICATE_ISSUED', ...) calls both
    // reading the same pre-write CASCADE_COMPLETE snapshot and both minting
    // a certificate. The CAS is scoped to exactly the status this call read
    // (request.status), which isValidTransition already confirmed can
    // legally move to newStatus; if the document has since moved past it,
    // some other caller won and this one backs off with the winner's state
    // instead of re-running the handler. See claimTransition's own
    // docstring for the compare-and-swap itself.
    const claimOrLose = async (): Promise<DeletionRequest | undefined> => {
      const result = await this.deletionRequestRepo.claimTransition(deletionRequestId, [request.status], newStatus);
      if (result.claimed) return undefined;
      logger.info(
        { deletionRequestId, userId: request.user_id, from: request.status, to: newStatus },
        'Lost the transition claim to a concurrent caller; returning its state instead of re-running this handler'
      );
      return result.current;
    };

    switch (newStatus) {
      case 'KEY_DESTROYED': {
        const lost = await claimOrLose();
        if (lost) return lost;

        try {
          // Perform irreversible key destruction
          await this.firestoreRegistry.shredKeyForUser(request.user_id, tenantId, deletionRequestId);
        } catch (err) {
          // The claim above already committed status: KEY_DESTROYED, but
          // the key was never actually destroyed -- roll the document back
          // to the status this claim moved it from rather than leave it
          // falsely marked as key-destroyed. Safe to write unconditionally:
          // claimTransition's CAS guaranteed this call is the only one that
          // ever saw the document at request.status for this transition, so
          // nothing else can be racing this rollback.
          logger.error({ err, deletionRequestId, userId: request.user_id }, 'Key destruction failed after winning the transition claim -- rolling back status');
          await this.deletionRequestRepo.updateDeletionRequestStatus(deletionRequestId, request.status, {});
          throw err;
        }
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
        await this.deletionRequestRepo.updateDeletionRequestFields(deletionRequestId, updateFields);
        return { ...request, ...updateFields, status: newStatus };
      }
      case 'CASCADE_PENDING': {
        const plan = await this.prepareCascadeTrigger(deletionRequestId, request, tenantId, operationId);
        if (plan.shortcutToComplete) {
          logger.info({ userId: request.user_id }, 'No SaaS tasks or source redactions found, advancing to complete');
          // If no SaaS cleanup or source redaction is needed, move straight to COMPLETE
          return this.shortcutToCascadeComplete(deletionRequestId, operationId);
        }
        if (plan.planFailed) {
          // Building the cleanup plan itself threw (e.g. createCleanupPlan /
          // planRedaction / planEncryptedCopyDeletion) -- before this, that
          // exception would propagate straight out of advanceRequest, this
          // status write below would never run, and the request would be
          // stuck at KEY_DESTROYED forever with no cascade ever attempted
          // and no automated reconciliation to notice. KEY_DESTROYED ->
          // CASCADE_PARTIAL_FAILURE is a valid transition, so force it
          // instead -- same "representable, not hidden" principle the async
          // cleanup-loop failure below already gets.
          logger.error(
            { deletionRequestId, userId: request.user_id, err: plan.error },
            'Cascade plan creation failed before any wipe was dispatched -- advancing to CASCADE_PARTIAL_FAILURE instead of leaving the request stuck at KEY_DESTROYED'
          );
          return this.advanceRequest(deletionRequestId, 'CASCADE_PARTIAL_FAILURE', operationId, {
            failedDestinations: [`internal-error (plan creation): ${plan.error instanceof Error ? plan.error.message : String(plan.error)}`],
          });
        }

        // Claimed only once we know this is the real (non-shortcut) path --
        // deliberately placed after plan-building rather than at the top of
        // this case, so the shortcut above keeps writing straight to
        // CASCADE_COMPLETE with no extra CASCADE_PENDING write in between,
        // exactly as before. Plan-building itself is read-only (no wipes
        // dispatched yet), so racing it twice is harmless either way; what
        // this guards is the actual cascade dispatch below.
        const lost = await claimOrLose();
        if (lost) return lost;

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
        await this.deletionRequestRepo.updateDeletionRequestFields(deletionRequestId, updateFields);
        afterStatusPersisted?.();
        return { ...request, ...updateFields, status: newStatus };
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
          return this.shortcutToCascadeComplete(deletionRequestId, operationId);
        }
        if (plan.planFailed) {
          // Unlike the CASCADE_PENDING case above, there's no valid
          // CASCADE_PARTIAL_FAILURE -> CASCADE_PARTIAL_FAILURE self-transition
          // (isValidTransition has no self-loop) -- and none is needed. The
          // request is already sitting at CASCADE_PARTIAL_FAILURE, which is
          // how a retry gets triggered at all; that's already the correct,
          // visible, retriable state. Log and return the request unchanged
          // rather than writing CASCADE_IN_PROGRESS for a retry that never
          // actually started.
          logger.error(
            { deletionRequestId, userId: request.user_id, err: plan.error },
            'Cascade retry plan creation failed -- leaving request at CASCADE_PARTIAL_FAILURE for a future retry'
          );
          return request;
        }

        // See the matching comment in CASCADE_PENDING above -- claimed
        // after plan-building, for the same reason.
        const lost = await claimOrLose();
        if (lost) return lost;

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
        await this.deletionRequestRepo.updateDeletionRequestFields(deletionRequestId, updateFields);
        afterStatusPersisted?.();
        return { ...request, ...updateFields, status: newStatus };
      }
      case 'CASCADE_COMPLETE':
        // When cascade is done, automatically move to certificate issuance.
        // No claim here -- this always writes unconditionally and
        // immediately recurses into CERTIFICATE_ISSUED, which claims for
        // itself; that's the transition whose side effect (minting a
        // certificate) actually can't fire twice, and it's guarded either
        // way this one lands.
        await this.deletionRequestRepo.updateDeletionRequestStatus(deletionRequestId, newStatus, updateFields);
        return this.advanceRequest(deletionRequestId, 'CERTIFICATE_ISSUED', operationId);

      case 'CASCADE_PARTIAL_FAILURE': {
        const lost = await claimOrLose();
        if (lost) return lost;

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
        await this.deletionRequestRepo.updateDeletionRequestFields(deletionRequestId, updateFields);
        return { ...request, ...updateFields, status: newStatus };
      }

      case 'CERTIFICATE_ISSUED': {
        const lost = await claimOrLose();
        if (lost) return lost;

        // Generate and store the certificate in GCS as required by infra.
        // The claim above is the exclusive gate -- only the caller that
        // won it reaches this line, so issueAndStoreCertificate can never
        // fire twice for one CASCADE_COMPLETE -> CERTIFICATE_ISSUED
        // transition, even when two callers raced off the same stale read.
        let gcsPath: string;
        try {
          ({ gcsPath } = await this.certificateService.issueAndStoreCertificate(request.user_id, request.deletion_request_id, tenantId));
        } catch (err) {
          // Same rollback reasoning as KEY_DESTROYED above: the claim
          // already committed status: CERTIFICATE_ISSUED, but no
          // certificate was actually produced. Roll back to the status
          // this claim moved it from (CASCADE_COMPLETE) and rethrow, so
          // prepareCascadeTrigger's own recovery catch runs exactly as it
          // did before this fix -- forcing a visible CASCADE_PARTIAL_FAILURE
          // with the real error message, instead of leaving the document
          // stuck falsely claiming a certificate that doesn't exist.
          logger.error({ err, deletionRequestId, userId: request.user_id }, 'Certificate issuance failed after winning the transition claim -- rolling back status');
          await this.deletionRequestRepo.updateDeletionRequestStatus(deletionRequestId, request.status, {});
          throw err;
        }

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
        await this.deletionRequestRepo.updateDeletionRequestFields(deletionRequestId, updateFields);
        return { ...request, ...updateFields, status: newStatus };
      }
      // Other states (e.g. SHRED_REQUESTED) have no dedicated handler and
      // fall through to the generic, unclaimed write below -- unchanged,
      // pre-existing behavior; out of scope for this fix.
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
  ): Promise<
    | { shortcutToComplete: true }
    | { shortcutToComplete: false; planFailed: true; error: unknown }
    | { shortcutToComplete: false; planFailed: false; afterStatusPersisted: () => void; taskDestinations: string[] }
  > {
    let tasks: Awaited<ReturnType<JanitorService['createCleanupPlan']>>;
    let redactionResources: ReturnType<NonNullable<SourceRedactionService['planRedaction']>>;
    let encryptedCopyResources: ReturnType<NonNullable<SourceRedactionService['planEncryptedCopyDeletion']>>;
    try {
      tasks = await this.janitorService.createCleanupPlan(request.user_id, tenantId);
      redactionResources = this.sourceRedactionService?.planRedaction(tenantId) ?? [];
      encryptedCopyResources = this.sourceRedactionService?.planEncryptedCopyDeletion(tenantId) ?? [];
    } catch (err) {
      logger.error({ err, userId: request.user_id, deletionRequestId }, 'Failed to build cascade cleanup plan');
      return { shortcutToComplete: false, planFailed: true, error: err };
    }

    if (tasks.length === 0 && redactionResources.length === 0 && encryptedCopyResources.length === 0) {
      return { shortcutToComplete: true };
    }

    const afterStatusPersisted = () => {
      Promise.all([
        this.janitorService.processCleanup(request.user_id, tenantId),
        redactionResources.length > 0 && this.sourceRedactionService
          ? this.sourceRedactionService.redactUserInDeclaredSources(request.user_id, tenantId)
          : Promise.resolve([]),
        encryptedCopyResources.length > 0 && this.sourceRedactionService
          ? this.sourceRedactionService.deleteUserFromEncryptedCopies(request.user_id, tenantId)
          : Promise.resolve([]),
      ]).then(async ([janitorResults, redactionResults, encryptedCopyResults]) => {
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
        // Source-redaction resources are tracked the same way, using the
        // resource id as the destination label -- a redaction failure
        // withholds the certificate exactly like a SaaS wipe failure
        // already does, since both mean the user's data demonstrably
        // still exists somewhere Chameleon knows about. Suffixed with
        // the strategy name: strategies are independently combinable now
        // (see resolveSourceRedactionStrategies), so the same resourceId
        // can legitimately appear in both redactionResults and
        // encryptedCopyResults in one cascade run, and an unsuffixed key
        // would let the second write silently clobber the first's
        // recorded status instead of tracking both.
        for (const result of redactionResults) {
          await this.updateJanitorWipeStatus(
            deletionRequestId,
            `${result.resourceId}::REDACT_IN_PLACE`,
            result.success ? 'SUCCEEDED' : 'FAILED',
            { rowsAffected: result.rowsAffected, error: result.error }
          ).catch(err => logger.error({ err, destination: result.resourceId }, 'Failed to record source redaction status'));
        }
        for (const result of encryptedCopyResults) {
          await this.updateJanitorWipeStatus(
            deletionRequestId,
            `${result.resourceId}::ENCRYPTED_COPY`,
            result.success ? 'SUCCEEDED' : 'FAILED',
            { rowsAffected: result.rowsAffected, error: result.error }
          ).catch(err => logger.error({ err, destination: result.resourceId }, 'Failed to record encrypted-copy deletion status'));
        }

        const failedJanitor = janitorResults.filter(r => r.status !== 'COMPLETE');
        const failedRedaction = redactionResults.filter(r => !r.success);
        const failedEncryptedCopy = encryptedCopyResults.filter(r => !r.success);
        const nextStatus: DeletionRequestStatus =
          failedJanitor.length > 0 || failedRedaction.length > 0 || failedEncryptedCopy.length > 0
            ? 'CASCADE_PARTIAL_FAILURE'
            : 'CASCADE_COMPLETE';
        await this.advanceRequest(deletionRequestId, nextStatus, operationId, {
          failedDestinations: [
            ...failedJanitor.map(r => r.destination),
            ...failedRedaction.map(r => `${r.resourceId}::REDACT_IN_PLACE`),
            ...failedEncryptedCopy.map(r => `${r.resourceId}::ENCRYPTED_COPY`),
          ],
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

    return { shortcutToComplete: false, planFailed: false, afterStatusPersisted, taskDestinations: tasks.map(t => t.destination) };
  }

  /**
   * The ONLY legitimate way to reach CASCADE_COMPLETE without going through
   * CASCADE_PENDING/CASCADE_IN_PROGRESS's normal post-cascade path -- used
   * exclusively by prepareCascadeTrigger's own two shortcut call sites,
   * immediately after it has itself just confirmed (via a real
   * createCleanupPlan/planRedaction/planEncryptedCopyDeletion check) that
   * there is nothing to clean up for this user. Deliberately bypasses
   * isValidTransition's public table, which does NOT allow KEY_DESTROYED or
   * CASCADE_PARTIAL_FAILURE to jump straight to CASCADE_COMPLETE for an
   * externally-driven /advance call.
   *
   * That gap was real and exploitable, not hypothetical: any caller with
   * access to POST /deletion-requests/:id/advance (today, just the shared
   * VAULT_API_KEY) could call newStatus=CASCADE_COMPLETE or
   * newStatus=CERTIFICATE_ISSUED directly from KEY_DESTROYED and receive a
   * real, signed Certificate of Destruction WITHOUT the janitor/source-
   * redaction cascade ever having run -- for a user who might still have
   * live data in HubSpot, Salesforce, or a REDACT_IN_PLACE-declared source
   * table. Found 2026-08-24 while scoping external-system deletion access;
   * unrelated to that feature and exploitable today via existing
   * credentials. Closed by removing those two entries from
   * KEY_DESTROYED's row in isValidTransition and routing the one
   * legitimate internal use through this method instead.
   *
   * Bonus fix, found the same way: before this, the CASCADE_IN_PROGRESS
   * retry's identical shortcut (line above) would have thrown
   * "Invalid state transition from CASCADE_PARTIAL_FAILURE to
   * CASCADE_COMPLETE" the moment a retry found nothing left to wipe --
   * CASCADE_PARTIAL_FAILURE -> CASCADE_COMPLETE was never in the public
   * table at all. Untested (no existing test drove a retry into an empty
   * plan), so this was silently broken. This method fixes that too, for
   * free, since it never consults the FROM status.
   */
  private async shortcutToCascadeComplete(deletionRequestId: string, operationId: string): Promise<DeletionRequest> {
    await this.deletionRequestRepo.updateDeletionRequestStatus(deletionRequestId, 'CASCADE_COMPLETE', {});
    return this.advanceRequest(deletionRequestId, 'CERTIFICATE_ISSUED', operationId);
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
    // This table governs every EXTERNALLY-DRIVEN /advance call (and the
    // normal post-cascade CASCADE_PENDING/CASCADE_IN_PROGRESS -> COMPLETE
    // transition, once a real cascade genuinely ran). It deliberately does
    // NOT allow KEY_DESTROYED -> CASCADE_COMPLETE/CERTIFICATE_ISSUED --
    // those direct jumps used to be listed here as a "shortcut for users
    // without SaaS lineage," but they let ANY caller mint a real signed
    // certificate without the cascade ever running or being checked at
    // all. The equivalent, actually-verified shortcut (confirm nothing
    // needs cleaning up, THEN complete) already exists and is the only way
    // to reach it now: shortcutToCascadeComplete(), called exclusively
    // from inside prepareCascadeTrigger's own two callers, immediately
    // after that real check. See shortcutToCascadeComplete's docstring.
    const transitions: Record<DeletionRequestStatus, DeletionRequestStatus[]> = {
      'SHRED_REQUESTED': ['KEY_DESTROYED', 'CASCADE_PARTIAL_FAILURE'],
      'KEY_DESTROYED': ['CASCADE_PENDING', 'CASCADE_PARTIAL_FAILURE'],
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

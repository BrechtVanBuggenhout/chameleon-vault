import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { PubSubDLQClient } from '../gcp/pubsub-dlq-client.js';
import { createLogger } from '../logging/index.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import type { JanitorTask } from '../types/janitor.js';
import { BigQueryLineageRepository } from '../gcp/bigquery-lineage.js';
import { connectorRegistry } from './registry.js';
import type { WipeResult } from './connectors/types.js';

const logger = createLogger('janitor-service');

export class JanitorService {
  private readonly MAX_RETRIES = 3;

  constructor(
    private readonly registry: FirestoreRegistry,
    private readonly lineageRepo: BigQueryLineageRepository,
    private readonly dekKmsClient: CloudKMSClient,
    private readonly dlqClient: PubSubDLQClient
  ) {}

  async createCleanupPlan(userId: string, tenantId: string = 'default-tenant'): Promise<JanitorTask[]> {
    // PERFORMANCE: Read destinations from Firestore (Hot Path) instead of BigQuery.
    // Latency drops from ~2000ms (BQ) to ~10ms (Firestore).
    const keyStatus = await this.registry.getKeyStatus(userId, tenantId);
    const destinations = keyStatus?.destinations || []; 

    logger.debug({ userId, foundDestinations: destinations }, 'Janitor analyzing destinations from Hot-Path');

    const tasks = destinations
      .filter((destName) => {
        const hasConnector = connectorRegistry.getConnector(destName) !== undefined;
        if (!hasConnector) {
          logger.debug({ userId, destination: destName }, 'Skipping destination: No SaaS connector registered');
        }
        return hasConnector;
      })
      .map((destName) => ({
        userId,
        destination: destName,
        status: 'PENDING' as const,
        attempts: 0,
      }));

    logger.info({ userId, taskCount: tasks.length, destinations: tasks.map(t => t.destination) }, 'Cleanup plan created by Janitor');
    return tasks;
  }

  async processCleanup(userId: string, tenantId: string = 'default-tenant'): Promise<JanitorTask[]> {
    const tasks = await this.createCleanupPlan(userId, tenantId);
    const results: JanitorTask[] = [];

    for (const task of tasks) {
      const connector = connectorRegistry.getConnector(task.destination);
      if (!connector) {
        logger.error({ userId, destination: task.destination }, 'No connector found during processing');
        results.push({ ...task, status: 'FAILED' });
        continue;
      }

      let success = false;
      let attempts = 0;
      let lastError = '';
      let recordsFound: number | undefined;

      while (attempts < this.MAX_RETRIES && !success) {
        attempts++;
        logger.info({ userId, destination: task.destination, attempt: attempts }, 'Janitor dispatching wipe request');
        
        // Report SaaS_WIPE_STARTED
        await this.lineageRepo.recordEvent({
          userId,
          tenantId,
          source: 'janitor-service',
          destination: task.destination,
          eventType: 'SaaS_WIPE_STARTED',
          context: {
            destination_system: task.destination,
            attempt: attempts
          }
        }).catch(err => logger.error({ err }, 'Failed to record SaaS_WIPE_STARTED'));

        // Today's connectors always catch internally and return
        // {success:false, error}, but that's an unenforced invariant, not a
        // guarantee -- a future connector (or an unexpected error class,
        // e.g. a DNS failure axios doesn't wrap the way we expect) could
        // throw instead. Treat a throw identically to a failure response
        // rather than letting it escape: an uncaught exception here would
        // reject processCleanup's caller's Promise.all, silently stalling
        // the whole deletion cascade at CASCADE_PENDING forever with no
        // visible failure state (see deletion-request-service.ts).
        const response: WipeResult = await connector.wipe(userId, tenantId).catch((err: unknown) => ({
          success: false as const,
          destination: task.destination,
          error: err instanceof Error ? err.message : String(err),
        }));

        if (response.success) {
          success = true;
          recordsFound = response.recordsFound;
          logger.info({ userId, destination: task.destination, attempts }, 'Janitor wipe successful');
        } else {
          lastError = response.error || 'Unknown error';

          // Trust the connector's own real classification (see
          // hubspot-connector.ts/salesforce-connector.ts, both derive this
          // from the actual HTTP status they saw: 429/5xx retryable,
          // 401/403 permanent) instead of re-deriving one from the error
          // message text here. The old re-derivation matched neither
          // connector's real message format -- HubSpot's error.message is
          // axios's own text (never contains the literal substring
          // "rate limit"), and Salesforce's is "Rate limited"/"Server error
          // (503)" (capital R, never the literal "500") -- so isRetryable
          // was effectively always false: every failure got zero backoff
          // delay regardless of whether it was actually transient, while
          // permanently-broken auth still got hammered for all
          // MAX_RETRIES attempts since the loop only skips the *delay*, not
          // the retry itself. Falls back to retryable when a connector
          // doesn't set the field at all (the .catch() below for an
          // unexpected thrown error, not a connector's own classified
          // response) -- an unrecognized failure is more likely a
          // transient blip than provably permanent, and a wrongly-retried
          // permanent failure just self-limits at MAX_RETRIES, while a
          // wrongly-skipped retry on a real transient failure fails the
          // whole cascade unnecessarily.
          const isRetryable = response.retryable ?? true;

          logger.warn({ userId, destination: task.destination, attempt: attempts, error: lastError, isRetryable }, 'Janitor wipe attempt failed');

          // A non-retryable failure (permanently broken auth, most often)
          // stops here instead of burning through the remaining attempts
          // immediately -- classifying it correctly above only fixed
          // whether a *delay* happens before the next attempt; the loop's
          // own condition never actually gated the retry on this at all,
          // so a real 401/403 still got hammered 3 times back-to-back with
          // zero delay between them. That's a real trust problem, not just
          // a performance one: the customer's own SaaS admin sees 3 rapid
          // failed calls from Chameleon's connector on their side, for a
          // problem retrying can never fix. One attempt, then stop.
          if (!isRetryable) {
            break;
          }

          if (attempts < this.MAX_RETRIES) {
            // Exponential backoff with jitter
            const delay = (Math.pow(2, attempts) * 1000) + (Math.random() * 1000);
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      }

      const finalStatus = success ? 'COMPLETE' : 'FAILED';
      results.push({
        ...task,
        status: finalStatus,
        attempts,
        recordsFound,
      });

      // Report SaaS_WIPE_COMPLETED
      await this.lineageRepo.recordEvent({
        userId,
        tenantId,
        source: 'janitor-service',
        destination: task.destination,
        eventType: 'SaaS_WIPE_COMPLETED',
        context: {
          destination_system: task.destination,
          status: finalStatus
        }
      }).catch(err => logger.error({ err }, 'Failed to record SaaS_WIPE_COMPLETED'));

      if (!success) {
        logger.error({ userId, destination: task.destination, attempts, error: lastError }, 'Janitor wipe permanently failed after retries');

        // Publish to Dead Letter Queue for audit and recovery
        try {
          await this.dlqClient.publishFailedWipe({
            userId,
            destination: task.destination,
            error: lastError,
            timestamp: new Date().toISOString()
          });
        } catch (dlqError: unknown) {
          const err = dlqError as Error;
          logger.error({ userId, destination: task.destination, dlqError: err.message }, 'Failed to publish to DLQ');
          // Continue anyway - DLQ failure should not block the process
        }
      }
    }

    if (results.length === 0) {
      logger.info({ userId, event: 'NO_SAAS_CLEANUP_REQUIRED' }, 'No SaaS cleanup tasks required');
    }

    return results;
  }
}

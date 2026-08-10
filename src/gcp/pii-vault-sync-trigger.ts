import { GoogleAuth } from 'google-auth-library';
import { createLogger } from '../logging/index.js';

const logger = createLogger('pii-vault-sync-trigger');

export interface SyncTriggerResult {
  status: string;
  resources_queued: number;
  chunks_queued: number;
  errors: Array<{ resourceId: string; error: string }>;
}

/**
 * Fires the same backfill/sync the daily Cloud Scheduler job invokes, on
 * demand -- so a newly-declared field or resource doesn't have to wait for
 * the next scheduled run.
 *
 * The worker's own endpoint only enumerates and fans out per-chunk work
 * over Pub/Sub, then returns immediately -- it does not wait for the
 * actual encrypt-diff-insert work to finish, so this result is a queued
 * count, not a final one. That's deliberate: enumeration is fast
 * regardless of table size, which is what lets this call return quickly
 * even for a resource with hundreds of thousands of users.
 *
 * The worker's URL is deliberately NOT passed in as config -- the worker
 * already depends on Key Vault's own URL (for its VAULT_BASE_URL env var),
 * so the reverse reference would be a Terraform dependency cycle. Instead
 * this resolves the worker's real URL itself at runtime via the Cloud Run
 * Admin API (needs `roles/run.viewer` on the worker), from plain,
 * dependency-free config: project ID, region, and the worker's service
 * name. That resolved URL is then used both as the OIDC audience and as the
 * call target -- the same auth mechanism Cloud Scheduler already uses to
 * invoke the worker (needs `roles/run.invoker` too).
 */
export class PiiVaultSyncTrigger {
  private readonly auth = new GoogleAuth();
  private cachedWorkerUrl: string | undefined;

  constructor(
    private readonly projectId: string,
    private readonly region: string,
    private readonly serviceName: string
  ) {}

  private async resolveWorkerUrl(): Promise<string> {
    if (this.cachedWorkerUrl) return this.cachedWorkerUrl;

    const client = await this.auth.getClient();
    const adminApiUrl = `https://run.googleapis.com/v2/projects/${this.projectId}/locations/${this.region}/services/${this.serviceName}`;
    const response = await client.request<{ uri?: string }>({ url: adminApiUrl });
    const uri = response.data.uri;
    if (!uri) {
      throw new Error(`Cloud Run Admin API returned no uri for service ${this.serviceName}`);
    }

    this.cachedWorkerUrl = uri;
    return uri;
  }

  /**
   * @param resourceId When given, scopes the sync to just this one
   * manually-declared resource instead of every declared resource for the
   * tenant -- the console's per-row "Sync now" action.
   */
  async trigger(resourceId?: string): Promise<SyncTriggerResult> {
    const workerUrl = await this.resolveWorkerUrl();
    const idTokenClient = await this.auth.getIdTokenClient(workerUrl);
    const response = await idTokenClient.request<SyncTriggerResult>({
      url: `${workerUrl}/api/v1/pii-vault-sync`,
      method: 'POST',
      // Always a full scan, never the daily job's incremental (watermark)
      // path -- Sync Now is the customer's manual "did I miss something"
      // lever (e.g. right after declaring a new field on an
      // already-synced resource), which an incremental scan wouldn't
      // catch since it has no concept of "field added, not row changed".
      // The Cloud Scheduler-invoked daily run omits this entirely, which
      // the worker treats as false.
      data: { force_full_scan: true, ...(resourceId ? { resource_id: resourceId } : {}) },
    });
    logger.info({ result: response.data, resourceId }, 'On-demand PII vault sync triggered');
    return response.data;
  }
}

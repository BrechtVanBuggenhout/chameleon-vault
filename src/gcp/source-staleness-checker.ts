import { GoogleAuth } from 'google-auth-library';
import { createLogger } from '../logging/index.js';

const logger = createLogger('source-staleness-checker');

export interface SourceStalenessResult {
  status: 'ok' | 'not_applicable';
  results?: Record<string, { status: 'stale' | 'current' | 'unknown'; builtSha?: string; latestSha?: string; reason?: string }>;
}

/**
 * Proxies the PII Ingestor Worker's POST /api/v1/source-staleness-check --
 * lets the console show "is this BYOC install running current code" without
 * needing its own Cloud Run invoker grant on the worker. Same
 * resolve-the-worker-URL-via-Admin-API + OIDC pattern as
 * PiiVaultSyncTrigger, deliberately not shared code with it since each is a
 * small, single-purpose class matching this codebase's existing convention.
 */
export class SourceStalenessChecker {
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

  async check(): Promise<SourceStalenessResult> {
    const workerUrl = await this.resolveWorkerUrl();
    const idTokenClient = await this.auth.getIdTokenClient(workerUrl);
    const response = await idTokenClient.request<SourceStalenessResult>({
      url: `${workerUrl}/api/v1/source-staleness-check`,
      method: 'POST',
    });
    logger.info({ result: response.data }, 'Source staleness check proxied');
    return response.data;
  }
}

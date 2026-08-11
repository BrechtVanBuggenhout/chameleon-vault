/**
 * One record per triggered pii_vault sync (scheduled or Sync Now),
 * so the console can poll real progress instead of showing a static
 * "queued N chunk(s)" message. Owned by chameleon-key-vault (not
 * chameleon-data-pipelines, which has no existing Firestore client code)
 * -- data-pipelines creates and updates these through the routes in
 * routes/sync-runs.ts, the same worker-auth pattern as mark-synced.
 *
 * chunksTotal starts null: the enumeration that discovers how many chunks
 * a run will publish can take a while for a large resource, and the first
 * chunk can already be processed by Pub/Sub before enumeration finishes.
 * Progress increments are accepted regardless of whether the total is
 * known yet; finalizeTotal() and recordChunkOutcome() each independently
 * check "are we done" so the run completes correctly no matter which one
 * observes the last chunk.
 */
export type SyncRunStatus = 'enumerating' | 'running' | 'complete';

export interface SyncRun {
  runId: string;
  tenantId: string;
  /** Set only for a single-resource Sync Now; absent for a full scheduled run. */
  resourceId?: string;
  status: SyncRunStatus;
  chunksTotal: number | null;
  chunksCompleted: number;
  /**
   * Informational only -- a chunk that fails is retried by Pub/Sub (see
   * pii_vault_sync_chunk_worker_push's retry_policy), so a "failed" report
   * here is not necessarily terminal for that chunk. Only chunksCompleted
   * counts toward chunksTotal for finishing the run.
   */
  chunksFailed: number;
  startedAt: string;
  completedAt?: string;
}

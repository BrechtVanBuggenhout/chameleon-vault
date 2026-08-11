import { Firestore } from '@google-cloud/firestore';
import type { SyncRun } from '../types/sync-run.js';

/**
 * Firestore-backed store for sync_runs (see types/sync-run.ts). One document
 * per run, keyed by runId (a UUID data-pipelines generates once per
 * /pii-vault-sync HTTP call) -- no compound key needed, runId is already
 * globally unique.
 */
export class SyncRunRepository {
  private readonly db: Firestore;

  constructor(
    projectId: string,
    private readonly collectionName: string,
    databaseId?: string
  ) {
    this.db = new Firestore({ projectId, ...(databaseId && { databaseId }) });
  }

  async create(input: { runId: string; tenantId: string; resourceId?: string }): Promise<SyncRun> {
    const run: SyncRun = {
      runId: input.runId,
      tenantId: input.tenantId,
      ...(input.resourceId && { resourceId: input.resourceId }),
      status: 'enumerating',
      chunksTotal: null,
      chunksCompleted: 0,
      chunksFailed: 0,
      startedAt: new Date().toISOString(),
    };
    await this.db.collection(this.collectionName).doc(run.runId).set(run);
    return run;
  }

  async get(runId: string): Promise<SyncRun | null> {
    const snapshot = await this.db.collection(this.collectionName).doc(runId).get();
    return snapshot.exists ? (snapshot.data() as SyncRun) : null;
  }

  /**
   * Called once enumeration finishes and the real chunk count is known.
   * If every chunk already reported completed by the time this lands (a
   * real possibility for a small, fast run), finalizes the run immediately
   * instead of leaving it stuck at "running" with nothing left to push it
   * over the line.
   */
  async finalizeTotal(runId: string, chunksTotal: number): Promise<SyncRun | null> {
    const docRef = this.db.collection(this.collectionName).doc(runId);
    return this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(docRef);
      if (!snapshot.exists) {
        return null;
      }
      const current = snapshot.data() as SyncRun;
      const done = current.chunksCompleted >= chunksTotal;
      const updates: Partial<SyncRun> = {
        chunksTotal,
        status: done ? 'complete' : 'running',
        ...(done && !current.completedAt ? { completedAt: new Date().toISOString() } : {}),
      };
      transaction.set(docRef, updates, { merge: true });
      return { ...current, ...updates };
    });
  }

  /**
   * Best-effort per-chunk progress report from process_chunk. Returns null
   * (rather than throwing) when the run doc doesn't exist -- a failure here
   * must never fail the chunk's actual sync work, so the caller treats a
   * missing run the same as any other non-fatal reporting gap.
   */
  async recordChunkOutcome(runId: string, outcome: 'completed' | 'failed'): Promise<SyncRun | null> {
    const docRef = this.db.collection(this.collectionName).doc(runId);
    return this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(docRef);
      if (!snapshot.exists) {
        return null;
      }
      const current = snapshot.data() as SyncRun;
      const chunksCompleted = current.chunksCompleted + (outcome === 'completed' ? 1 : 0);
      const chunksFailed = current.chunksFailed + (outcome === 'failed' ? 1 : 0);
      const done = current.chunksTotal !== null && chunksCompleted >= current.chunksTotal;
      const updates: Partial<SyncRun> = {
        chunksCompleted,
        chunksFailed,
        ...(done ? { status: 'complete', completedAt: new Date().toISOString() } : {}),
      };
      transaction.set(docRef, updates, { merge: true });
      return { ...current, ...updates };
    });
  }
}

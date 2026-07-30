export type JanitorTaskStatus = 'PENDING' | 'QUEUED' | 'COMPLETE' | 'FAILED';

export interface JanitorTask {
  userId: string;
  destination: string;
  status: JanitorTaskStatus;
  attempts: number;
  /** How many records the connector actually found and deleted, when known. See WipeResult. */
  recordsFound?: number;
}

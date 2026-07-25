export type JanitorTaskStatus = 'PENDING' | 'QUEUED' | 'COMPLETE' | 'FAILED';

export interface JanitorTask {
  userId: string;
  destination: string;
  status: JanitorTaskStatus;
  attempts: number;
}

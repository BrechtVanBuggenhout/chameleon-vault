export type DeletionRequestStatus =
  | 'SHRED_REQUESTED'
  | 'KEY_DESTROYED'
  | 'CASCADE_PENDING'
  | 'CASCADE_IN_PROGRESS'
  | 'CASCADE_COMPLETE'
  | 'CASCADE_PARTIAL_FAILURE'
  | 'CERTIFICATE_ISSUED';

export interface DeletionRequest {
  deletion_request_id: string;
  tenant_id?: string;
  user_id: string;
  status: DeletionRequestStatus;
  created_at: Date;
  status_history: Array<{ status: DeletionRequestStatus; timestamp: Date }>;
  janitor_wipes: Array<{
    destination: string;
    status: 'PENDING' | 'IN_PROGRESS' | 'SUCCEEDED' | 'FAILED' | 'DLQ';
    updated_at: Date;
    details?: any;
  }>;
  key_destroyed_at?: Date;
  cascade_initiated_at?: Date;
  certificate_issued_at?: Date;
}

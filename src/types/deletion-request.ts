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
  // gs:// URI of the stored certificate JSON, set alongside
  // certificate_issued_at once issueAndStoreCertificate succeeds. Lets
  // GET /certificate/:userId return the exact certificate that was actually
  // issued (and chained) instead of re-signing a fresh one on every call.
  certificate_gcs_path?: string;
  /**
   * Email of whoever requested this deletion, when the creating call
   * carried a real, resolvable per-analyst or console-session credential
   * (see middleware/auth.ts). Absent for requests created with the shared
   * write token -- no individual to attribute -- or a machine caller
   * (e.g. a customer's own API integration), never a guessed identity.
   */
  requested_by?: string;
}

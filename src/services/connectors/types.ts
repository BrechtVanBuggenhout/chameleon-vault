export interface WipeResult {
  success: boolean;
  destination: string;
  error?: string;
  retryable?: boolean;
  /**
   * How many records were actually found and deleted. 0 means the wipe
   * genuinely succeeded but there was never any PII there to begin with --
   * a distinct outcome from having found and removed real data, and one a
   * Certificate of Destruction should be able to tell apart (see
   * certificate-service.ts's use of this to avoid claiming "ERASED" for a
   * destination that never held anything for this user).
   */
  recordsFound?: number;
}

export interface IWipeConnector {
  name: string;
  wipe(userId: string, tenantId: string): Promise<WipeResult>;
}
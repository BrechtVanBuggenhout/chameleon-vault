export interface WipeResult {
  success: boolean;
  destination: string;
  error?: string;
  retryable?: boolean;
}

export interface IWipeConnector {
  name: string;
  wipe(userId: string, tenantId: string): Promise<WipeResult>;
}
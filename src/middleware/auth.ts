import { AnalystAccessService } from '../services/analyst-access-service.js';

export interface AuthResult {
  authorized: boolean;
  analystEmail?: string;
}

// The claim-consumption route is the one place an anonymous caller (an
// analyst who has neither the shared key nor a credential yet) must be let
// through -- the one-time token in the URL is its own authorization there.
const CLAIM_ROUTE_PATTERN = /^\/admin\/analyst-claims\/[^/]+\/claim$/;

// A per-analyst credential is deliberately narrower than the shared key: it
// can only ever call the two routes that read/write plaintext on demand,
// never rotate/shred keys, mint more credentials, etc.
const ANALYST_CREDENTIAL_ALLOWED_PATHS = new Set(['/encrypt', '/decrypt']);

export function isExemptFromAuth(path: string): boolean {
  return path === '/health' || CLAIM_ROUTE_PATTERN.test(path);
}

export async function resolveAuth(
  path: string,
  providedKey: string | undefined,
  sharedApiKey: string,
  analystAccessService: AnalystAccessService
): Promise<AuthResult> {
  if (providedKey === sharedApiKey) {
    return { authorized: true };
  }

  if (providedKey && ANALYST_CREDENTIAL_ALLOWED_PATHS.has(path)) {
    const identity = await analystAccessService.resolveCredential(providedKey);
    if (identity) {
      return { authorized: true, analystEmail: identity.analystEmail };
    }
  }

  return { authorized: false };
}

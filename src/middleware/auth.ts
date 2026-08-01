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

// BigQuery's remote function has no way to present VAULT_API_KEY -- it
// authenticates as the connection's own service account via a Google-signed
// ID token instead. Exempt from the shared-key hook here; the route itself
// (decrypted-views-decrypt.ts) verifies that token as its actual auth,
// alongside Cloud Run IAM invoker at the platform layer. A third, distinct
// auth tier from shared-key and analyst-credential above -- deliberately so,
// since neither of those mechanisms fit a machine-to-machine BigQuery caller.
const DECRYPTED_VIEWS_BATCH_DECRYPT_PATH = '/internal/decrypted-views/batch-decrypt';

export function isExemptFromAuth(path: string): boolean {
  return path === '/health' || CLAIM_ROUTE_PATTERN.test(path) || path === DECRYPTED_VIEWS_BATCH_DECRYPT_PATH;
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

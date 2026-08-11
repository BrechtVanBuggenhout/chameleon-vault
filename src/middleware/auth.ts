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
// can call the two routes that read/write plaintext on demand, plus (for a
// real, attributable audit trail -- see routes/audit.ts) the routes that
// declare/update/remove a PII resource and create a deletion request. It can
// never rotate/shred keys, mint more analyst credentials, or reach any
// other admin route.
const ANALYST_CREDENTIAL_EXACT_PATHS = new Set([
  '/encrypt',
  '/decrypt',
  '/pii-registry/resources',
  '/deletion-requests',
]);

// PUT/DELETE /pii-registry/resources/:resourceId -- deliberately does NOT
// match /pii-registry/resources/:resourceId/mark-synced (an extra path
// segment), which stays shared-key-only: that route is a machine-to-machine
// sync-watermark update from chameleon-data-pipelines, not something an
// individual analyst declares.
const ANALYST_CREDENTIAL_RESOURCE_PATTERN = /^\/pii-registry\/resources\/[^/]+$/;

function isAnalystCredentialAllowedPath(path: string): boolean {
  return ANALYST_CREDENTIAL_EXACT_PATHS.has(path) || ANALYST_CREDENTIAL_RESOURCE_PATTERN.test(path);
}

// BigQuery's remote function has no way to present VAULT_API_KEY -- it
// authenticates as the connection's own service account via a Google-signed
// ID token instead. Exempt from the shared-key hook here; the route itself
// (decrypted-views-decrypt.ts) verifies that token as its actual auth,
// alongside Cloud Run IAM invoker at the platform layer. A third, distinct
// auth tier from shared-key and analyst-credential above -- deliberately so,
// since neither of those mechanisms fit a machine-to-machine BigQuery caller.
const DECRYPTED_VIEWS_BATCH_DECRYPT_PATH = '/internal/decrypted-views/batch-decrypt';

// The whole point of publishing these is zero-trust verification by someone
// who has never had a relationship with Chameleon -- an outside auditor who
// received a certificate JWT from a customer, with no VAULT_API_KEY of their
// own. Gating them behind the shared key would make that impossible while
// looking like it worked (verify-cert.ts would just 401 for exactly the
// audience it's meant to serve). Neither endpoint returns anything secret --
// a KMS asymmetric-sign public key and a JWKS document, by definition.
const PUBLIC_VERIFICATION_PATHS = new Set(['/public-key', '/.well-known/jwks.json']);

// Same reasoning as PUBLIC_VERIFICATION_PATHS above, for chain-continuity
// lookups: a hash is only ever known to someone who already holds a real
// chained certificate, so exposing this by-hash lookup unauthenticated
// doesn't let anyone enumerate a tenant's certificate history -- see
// CertificateChainEntry in types/certificate-chain.ts.
const CHAIN_BY_HASH_ROUTE_PATTERN = /^\/certificate-chain\/by-hash\/[^/]+$/;

export function isExemptFromAuth(path: string): boolean {
  return (
    path === '/health' ||
    path === '/version' ||
    CLAIM_ROUTE_PATTERN.test(path) ||
    path === DECRYPTED_VIEWS_BATCH_DECRYPT_PATH ||
    PUBLIC_VERIFICATION_PATHS.has(path) ||
    CHAIN_BY_HASH_ROUTE_PATTERN.test(path)
  );
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

  if (providedKey && isAnalystCredentialAllowedPath(path)) {
    const identity = await analystAccessService.resolveCredential(providedKey);
    if (identity) {
      return { authorized: true, analystEmail: identity.analystEmail };
    }
  }

  return { authorized: false };
}

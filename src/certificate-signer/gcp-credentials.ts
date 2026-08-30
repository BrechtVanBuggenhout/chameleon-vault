import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// GCP Confidential Space auto-writes a "default" attestation token to this
// fixed path, already scoped to the fixed audience GCP's own Workload
// Identity Federation expects -- see chameleon-paper/TEE_ATTESTATION_PLAN.md,
// Phase 2b. Wrapping a pointer to it in a standard external_account
// credential config is enough for google-auth-library's normal Application
// Default Credentials resolution to pick up automatically: KMS/Firestore
// clients (kms-client.ts, firestore-client.ts) construct with no explicit
// credentials today and don't need to change -- this just makes sure
// GOOGLE_APPLICATION_CREDENTIALS points at a real file before those
// constructors run their first API call. Not trust-critical code: this is
// infrastructure plumbing for how the process authenticates to GCP, not
// part of the certificate-issuance decision itself (see sign.ts's own
// comment for that boundary).
const DEFAULT_ATTESTATION_TOKEN_PATH = '/run/container_launcher/attestation_verifier_claims_token';

/**
 * When WORKLOAD_IDENTITY_PROVIDER is set (its full resource path, e.g.
 * "projects/.../locations/global/workloadIdentityPools/.../providers/..."
 * -- an operator-supplied value, since it depends on Terraform-created
 * resource IDs not known at image-build time), synthesizes the
 * external_account credential config GCP's client libraries expect and
 * points GOOGLE_APPLICATION_CREDENTIALS at it. A no-op outside Confidential
 * Space (local dev, the container smoke test in Phase 2a) -- ADC falls
 * back to its normal resolution in that case.
 */
export function configureWorkloadIdentityCredentialsIfPresent(): void {
  const workloadIdentityProvider = process.env.WORKLOAD_IDENTITY_PROVIDER;
  if (!workloadIdentityProvider) return;

  const config = {
    type: 'external_account',
    audience: `//iam.googleapis.com/${workloadIdentityProvider}`,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: 'https://sts.googleapis.com/v1/token',
    credential_source: { file: DEFAULT_ATTESTATION_TOKEN_PATH },
  };

  const credentialsPath = path.join(os.tmpdir(), 'workload-identity-credentials.json');
  fs.writeFileSync(credentialsPath, JSON.stringify(config));
  process.env.GOOGLE_APPLICATION_CREDENTIALS = credentialsPath;
}

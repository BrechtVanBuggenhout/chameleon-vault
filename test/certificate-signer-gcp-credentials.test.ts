import * as fs from 'fs';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';

import { configureWorkloadIdentityCredentialsIfPresent } from '../src/certificate-signer/gcp-credentials.js';

describe('configureWorkloadIdentityCredentialsIfPresent', () => {
  const ORIGINAL_ENV = { ...process.env };

  beforeEach(() => {
    delete process.env.WORKLOAD_IDENTITY_PROVIDER;
    delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  it('is a no-op when WORKLOAD_IDENTITY_PROVIDER is unset (local dev, Phase 2a smoke tests)', () => {
    configureWorkloadIdentityCredentialsIfPresent();
    expect(process.env.GOOGLE_APPLICATION_CREDENTIALS).toBeUndefined();
  });

  it('writes a valid external_account credential config pointing at the default attestation token, and sets GOOGLE_APPLICATION_CREDENTIALS to it', () => {
    process.env.WORKLOAD_IDENTITY_PROVIDER =
      'projects/123456789/locations/global/workloadIdentityPools/cert-signer-tee-dev-pool/providers/confidential-space';

    configureWorkloadIdentityCredentialsIfPresent();

    const credentialsPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    expect(credentialsPath).toBeDefined();

    const written = JSON.parse(fs.readFileSync(credentialsPath as string, 'utf8'));
    expect(written).toEqual({
      type: 'external_account',
      audience:
        '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/cert-signer-tee-dev-pool/providers/confidential-space',
      subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      token_url: 'https://sts.googleapis.com/v1/token',
      credential_source: { file: '/run/container_launcher/attestation_verifier_claims_token' },
    });
  });
});

import { KeyManagementServiceClient } from '@google-cloud/kms';
import * as crypto from 'crypto';

// The four operations CertificateSigner actually needs, nothing else --
// deliberately NOT a reuse of ../gcp/cloud-kms.ts's CloudKMSClient, even
// though that class already implements this same shape. Reusing it would
// transitively pull in ../crypto/deterministic-aes.ts (for a DEK-generation
// method this module never calls) and, through that, ../logging/index.js's
// @google-cloud/logging dependency -- exactly the unnecessary weight this
// module's whole design is meant to avoid. SigningKmsClient below is
// satisfied structurally by the real CloudKMSClient too (TypeScript
// structural typing), so main.ts's existing construction of CertificateSigner
// with a real CloudKMSClient instance needs zero changes -- this interface
// only matters for keeping this module's OWN standalone build minimal.
export interface SigningKmsClient {
  getCryptoKeyPath(): string;
  getNewestEnabledVersion(keyPath: string): Promise<string>;
  getPublicKey(keyVersionPath: string): Promise<string>;
  asymmetricSign(payload: string, keyVersionPath: string): Promise<string>;
}

function versionNumber(versionName: string): number {
  return Number(versionName.split('/').pop());
}

// A real, standalone implementation of SigningKmsClient for this module's
// own reproducible build (see Dockerfile.certificate-signer) -- not used by
// the parent monolith, which continues constructing its own CloudKMSClient
// exactly as before.
export class LocalSigningKmsClient implements SigningKmsClient {
  private client: KeyManagementServiceClient;

  constructor(
    private readonly projectId: string,
    private readonly region: string,
    private readonly keyRing: string,
    private readonly keyName: string
  ) {
    this.client = new KeyManagementServiceClient();
  }

  getCryptoKeyPath(): string {
    return this.client.cryptoKeyPath(this.projectId, this.region, this.keyRing, this.keyName);
  }

  async getNewestEnabledVersion(keyPath: string): Promise<string> {
    const versions: string[] = [];
    for await (const version of this.client.listCryptoKeyVersionsAsync({ parent: keyPath })) {
      if (version.state === 'ENABLED' && version.name) versions.push(version.name);
    }
    return [...versions].sort((a, b) => versionNumber(a) - versionNumber(b)).pop()!;
  }

  async getPublicKey(keyVersionPath: string): Promise<string> {
    const [publicKey] = await this.client.getPublicKey({ name: keyVersionPath });
    return publicKey.pem || '';
  }

  async asymmetricSign(payload: string, keyVersionPath: string): Promise<string> {
    const digest = crypto.createHash('sha256').update(payload).digest();
    const [signResponse] = await this.client.asymmetricSign({ name: keyVersionPath, digest: { sha256: digest } });
    if (!signResponse.signature) {
      throw new Error('Cloud KMS asymmetric signing failed');
    }
    return Buffer.from(signResponse.signature as Uint8Array).toString('base64url');
  }
}

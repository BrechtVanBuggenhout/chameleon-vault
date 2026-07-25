import { createRemoteJWKSet, jwtVerify } from 'jose';

/**
 * Verify a Project Chameleon Destruction Certificate
 * 
 * Usage:
 * npx tsx scripts/verify-cert.ts <JWT_TOKEN> [BASE_URL]
 */

const token = process.argv[2];
const baseUrl = process.argv[3] || 'http://localhost:8080';

if (!token) {
  console.error('\x1b[31mError: Missing JWT token.\x1b[0m');
  console.log('Usage: npx tsx scripts/verify-cert.ts <JWT_TOKEN> [BASE_URL]');
  process.exit(1);
}

async function verifyCertificate() {
  try {
    console.log(`\x1b[34m[*] Fetching JWKS from ${baseUrl}/.well-known/jwks.json...\x1b[0m`);
    
    // 1. Point to the remote JWKS endpoint
    const JWKS = createRemoteJWKSet(new URL(`${baseUrl}/.well-known/jwks.json`));

    // 2. Verify the JWT
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: 'Chameleon Key Vault',
      algorithms: ['PS256'],
    });

    console.log('\n\x1b[32m✅ Certificate Signature Verified Successfully!\x1b[0m');
    console.log('\x1b[36m--------------------------------------------------\x1b[0m');
    console.log(JSON.stringify(payload, null, 2));
    console.log('\x1b[36m--------------------------------------------------\x1b[0m');
    
    const shredDate = new Date(payload.shredDate as string);
    console.log(`\x1b[33mSummary:\x1b[0m User ${payload.sub} data was shredded on ${shredDate.toLocaleString()}.`);
    
  } catch (error: any) {
    console.error('\n\x1b[31m❌ Certificate Verification Failed!\x1b[0m');
    if (error.code === 'ERR_JWT_SIGNATURE_VERIFICATION_FAILED') {
      console.error('Reason: The signature does not match the public key.');
    } else if (error.code === 'ERR_JWKS_NO_MATCHING_KEY') {
      console.error('Reason: No matching key found in JWKS (Check the kid header).');
    } else {
      console.error(`Reason: ${error.message}`);
    }
    process.exit(1);
  }
}

verifyCertificate();
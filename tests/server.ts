/** Shared relying-party fixtures for server-side and client↔server tests. */
import { generateRegistrationOptions, verifyRegistrationResponse } from '@apps';
import { COSEAlgorithm } from '@libs';

import { type Alg, ORIGIN, RP_ID, SoftAuthenticator } from './authenticator.js';

import type { RelyingPartyConfig, ResolvedRelyingPartyConfig } from '@types';

export const TEST_RP: RelyingPartyConfig = {
  rpId: RP_ID,
  rpName: 'Example',
  origins: [ORIGIN],
};
export const TEST_USER = { name: 'alice@example.com', displayName: 'Alice' };

/** Register a fresh credential ("none" attestation) and return the authenticator and result. */
export async function registerCredential(
  config: ResolvedRelyingPartyConfig,
  alg: Alg = COSEAlgorithm.ES256,
) {
  const auth = await SoftAuthenticator.create(alg);
  const options = generateRegistrationOptions(config, { user: TEST_USER });
  const response = await auth.register(options);
  const result = await verifyRegistrationResponse(config, {
    response,
    expectedChallenge: options.challenge,
  });
  return { auth, result, options };
}

import {
  parseAuthenticatorData,
  parseClientDataJSON,
  parseCoseKey,
  verifyClientData,
  verifyCoseSignature,
  verifyRpIdHash,
  verifyUserFlags,
} from '@libs';
import {
  concatBytes,
  fromBase64Url,
  sha256,
  timingSafeEqual,
  toBytes,
  WebAuthnError,
} from '@utils';

import { makeChallenge } from '../challenge';
import { assertAuthenticationResponse, toDescriptors } from '../response';

import type {
  GenerateAuthenticationOptionsInput,
  PublicKeyCredentialRequestOptionsJSON,
  ResolvedRelyingPartyConfig,
  VerifiedAuthentication,
  VerifyAuthenticationInput,
} from '@types';

/** Build `PublicKeyCredentialRequestOptionsJSON` for `navigator.credentials.get()`. */
export function generateAuthenticationOptions(
  config: ResolvedRelyingPartyConfig,
  input: GenerateAuthenticationOptionsInput = {},
): PublicKeyCredentialRequestOptionsJSON {
  const allowCredentials = toDescriptors(input.allowCredentials);
  const hints = input.hints ?? config.hints;
  return {
    rpId: config.rpId,
    challenge: makeChallenge(config, input.challenge),
    timeout: input.timeout ?? config.timeout,
    userVerification: input.userVerification ?? config.userVerification,
    ...(allowCredentials.length > 0 ? { allowCredentials } : {}),
    ...(hints.length > 0 ? { hints: [...hints] } : {}),
    ...(input.extensions ? { extensions: input.extensions } : {}),
  };
}

/**
 * Verify an authentication ceremony (WebAuthn §7.2). Throws `WebAuthnError`
 * on failure. Persist `newCounter` and `backedUp` on success.
 */
export async function verifyAuthenticationResponse(
  config: ResolvedRelyingPartyConfig,
  input: VerifyAuthenticationInput,
): Promise<VerifiedAuthentication> {
  const { response, credential } = input;
  assertAuthenticationResponse(response);
  const { crypto } = config;

  // §7.2 steps 5–6: the credential must be the one we looked up.
  if (!timingSafeEqual(fromBase64Url(response.rawId), fromBase64Url(credential.id))) {
    throw new WebAuthnError(
      'CREDENTIAL_ID_MISMATCH',
      'Response does not belong to the supplied credential',
    );
  }
  const userHandle = response.response.userHandle;
  if (input.expectedUserHandle !== undefined && userHandle) {
    if (!timingSafeEqual(fromBase64Url(userHandle), toBytes(input.expectedUserHandle))) {
      throw new WebAuthnError(
        'USER_HANDLE_MISMATCH',
        'userHandle does not match the credential owner',
      );
    }
  }

  // §7.2 steps 10–15: client data
  const clientData = parseClientDataJSON(response.response.clientDataJSON);
  verifyClientData(clientData.data, {
    type: 'webauthn.get',
    challenge: input.expectedChallenge,
    origins: config.origins,
    allowCrossOrigin: config.allowCrossOrigin,
    allowedTopOrigins: config.allowedTopOrigins,
  });

  // §7.2 steps 15–18: authenticator data
  const rawAuthData = fromBase64Url(response.response.authenticatorData);
  const authData = parseAuthenticatorData(rawAuthData);
  await verifyRpIdHash(authData, config.rpId, crypto);
  verifyUserFlags(
    authData,
    input.requireUserVerification ?? config.requireUserVerification,
  );

  // §7.2 steps 19–20: signature over authData || SHA-256(clientDataJSON)
  const publicKey = parseCoseKey(toBytes(credential.publicKey));
  if (!config.supportedAlgorithms.includes(publicKey.alg)) {
    throw new WebAuthnError(
      'UNSUPPORTED_ALGORITHM',
      `Algorithm ${publicKey.alg} is no longer accepted`,
    );
  }
  const clientDataHash = await sha256(clientData.raw, crypto);
  await verifyCoseSignature({
    crypto,
    publicKey,
    signature: fromBase64Url(response.response.signature),
    data: concatBytes(rawAuthData, clientDataHash),
  });

  // §7.2 step 21: signature counter (0/0 is normal for synced passkeys)
  const stored = credential.counter;
  const received = authData.signCount;
  let counterWarning = false;
  if ((stored !== 0 || received !== 0) && received <= stored) {
    if (config.counterPolicy === 'strict') {
      throw new WebAuthnError(
        'COUNTER_REGRESSION',
        'Signature counter did not increase – the authenticator may be cloned',
      );
    }
    counterWarning = true;
  }

  return {
    credentialId: response.id,
    newCounter: Math.max(stored, received),
    userVerified: authData.flags.userVerified,
    deviceType: authData.flags.backupEligible ? 'multiDevice' : 'singleDevice',
    backupEligible: authData.flags.backupEligible,
    backedUp: authData.flags.backedUp,
    origin: clientData.data.origin,
    ...(userHandle ? { userHandle } : {}),
    ...(counterWarning ? { counterWarning } : {}),
  };
}

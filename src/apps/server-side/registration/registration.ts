import {
  parseAttestationObject,
  parseAuthenticatorData,
  parseClientDataJSON,
  parseCoseKey,
  verifyAttestationStatement,
  verifyClientData,
  verifyRpIdHash,
  verifyUserFlags,
} from '@libs';
import {
  formatUuid,
  fromBase64Url,
  isRecord,
  randomBytes,
  sha256,
  timingSafeEqual,
  toBase64Url,
  toBytes,
  WebAuthnError,
} from '@utils';

import { makeChallenge } from '../challenge/index.js';
import {
  assertRegistrationResponse,
  sanitizeTransports,
  toDescriptors,
} from '../response/index.js';

import type {
  AuthenticatorSelectionCriteria,
  GenerateRegistrationOptionsInput,
  PublicKeyCredentialCreationOptionsJSON,
  RegisteredCredential,
  ResolvedRelyingPartyConfig,
  VerifiedRegistration,
  VerifyRegistrationInput,
} from '@types';

const MAX_USER_ID_BYTES = 64;
const MAX_USER_NAME_LENGTH = 256;

/** Build `PublicKeyCredentialCreationOptionsJSON` for `navigator.credentials.create()`. */
export function generateRegistrationOptions(
  config: ResolvedRelyingPartyConfig,
  input: GenerateRegistrationOptionsInput,
): PublicKeyCredentialCreationOptionsJSON {
  const { user } = input;
  if (!isRecord(user) || typeof user.name !== 'string' || user.name.trim().length === 0) {
    throw new WebAuthnError('INVALID_INPUT', 'user.name is required');
  }
  if (user.name.length > MAX_USER_NAME_LENGTH) {
    throw new WebAuthnError(
      'INVALID_INPUT',
      `user.name exceeds ${MAX_USER_NAME_LENGTH} characters`,
    );
  }
  const userId =
    user.id === undefined ? randomBytes(32, config.crypto) : toBytes(user.id);
  if (userId.length === 0 || userId.length > MAX_USER_ID_BYTES) {
    throw new WebAuthnError('INVALID_INPUT', 'user.id must be 1..64 bytes');
  }

  const selection: AuthenticatorSelectionCriteria = {
    residentKey: 'preferred',
    userVerification: config.userVerification,
    ...config.authenticatorSelection,
    ...input.authenticatorSelection,
  };
  const authenticatorSelection: AuthenticatorSelectionCriteria = {
    ...selection,
    requireResidentKey: selection.residentKey === 'required',
  };

  const excludeCredentials = toDescriptors(input.excludeCredentials);
  const hints = input.hints ?? config.hints;

  return {
    rp: { id: config.rpId, name: config.rpName },
    user: {
      id: toBase64Url(userId),
      name: user.name,
      displayName: user.displayName ?? user.name,
    },
    challenge: makeChallenge(config, input.challenge),
    pubKeyCredParams: config.supportedAlgorithms.map((alg) => ({
      type: 'public-key',
      alg,
    })),
    timeout: input.timeout ?? config.timeout,
    attestation: input.attestation ?? config.attestation,
    authenticatorSelection,
    ...(excludeCredentials.length > 0 ? { excludeCredentials } : {}),
    ...(hints.length > 0 ? { hints: [...hints] } : {}),
    extensions: { credProps: true, ...input.extensions },
  };
}

/**
 * Verify a registration ceremony (WebAuthn §7.1). Throws `WebAuthnError` on
 * any failure; on success returns the credential to persist.
 */
export async function verifyRegistrationResponse(
  config: ResolvedRelyingPartyConfig,
  input: VerifyRegistrationInput,
): Promise<VerifiedRegistration> {
  const { response } = input;
  assertRegistrationResponse(response);
  const { crypto } = config;

  // §7.1 steps 5–11: client data
  const clientData = parseClientDataJSON(response.response.clientDataJSON);
  verifyClientData(clientData.data, {
    type: 'webauthn.create',
    challenge: input.expectedChallenge,
    origins: config.origins,
    allowCrossOrigin: config.allowCrossOrigin,
    allowedTopOrigins: config.allowedTopOrigins,
  });
  const clientDataHash = await sha256(clientData.raw, crypto);

  // §7.1 steps 12–17: authenticator data
  const attestationObject = parseAttestationObject(
    fromBase64Url(response.response.attestationObject),
  );
  const authData = parseAuthenticatorData(attestationObject.authData);
  await verifyRpIdHash(authData, config.rpId, crypto);
  verifyUserFlags(
    authData,
    input.requireUserVerification ?? config.requireUserVerification,
  );

  const attested = authData.attestedCredentialData;
  if (!attested) {
    throw new WebAuthnError(
      'INVALID_AUTHENTICATOR_DATA',
      'Attested credential data (AT) missing',
    );
  }
  if (!timingSafeEqual(attested.credentialId, fromBase64Url(response.rawId))) {
    throw new WebAuthnError(
      'CREDENTIAL_ID_MISMATCH',
      'Credential ID in authenticator data differs from rawId',
    );
  }

  // §7.1 step 18: algorithm allowlist
  const publicKey = parseCoseKey(attested.credentialPublicKey);
  if (!config.supportedAlgorithms.includes(publicKey.alg)) {
    throw new WebAuthnError(
      'UNSUPPORTED_ALGORITHM',
      `Algorithm ${publicKey.alg} was not requested`,
    );
  }
  const reportedAlg = response.response.publicKeyAlgorithm;
  if (reportedAlg !== undefined && reportedAlg !== publicKey.alg) {
    throw new WebAuthnError(
      'INVALID_PUBLIC_KEY',
      'publicKeyAlgorithm does not match the credential key',
    );
  }

  // §7.1 steps 19–22: attestation
  const attestation = await verifyAttestationStatement(
    {
      format: attestationObject.fmt,
      attStmt: attestationObject.attStmt,
      authData: attestationObject.authData,
      parsedAuthData: authData,
      clientDataHash,
      crypto,
      trustAnchors: config.trustAnchors,
      now: config.now(),
    },
    config.attestationVerifiers,
  );
  if (config.requireTrustedAttestation && !attestation.trusted) {
    throw new WebAuthnError(
      'ATTESTATION_UNTRUSTED',
      'Attestation does not chain to a trusted root',
    );
  }

  const rk = response.clientExtensionResults.credProps?.rk;
  const credential: RegisteredCredential = {
    id: response.id,
    publicKey: toBase64Url(attested.credentialPublicKey),
    algorithm: publicKey.alg,
    counter: authData.signCount,
    transports: sanitizeTransports(response.response.transports),
    aaguid: formatUuid(attested.aaguid),
    deviceType: authData.flags.backupEligible ? 'multiDevice' : 'singleDevice',
    backupEligible: authData.flags.backupEligible,
    backedUp: authData.flags.backedUp,
    ...(typeof rk === 'boolean' ? { discoverable: rk } : {}),
    ...(response.authenticatorAttachment === 'platform' ||
    response.authenticatorAttachment === 'cross-platform'
      ? { attachment: response.authenticatorAttachment }
      : {}),
  };

  return {
    credential,
    userVerified: authData.flags.userVerified,
    attestation: {
      format: attestationObject.fmt,
      type: attestation.type,
      trusted: attestation.trusted,
      trustPath: attestation.trustPath,
    },
    origin: clientData.data.origin,
  };
}

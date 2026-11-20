import { copyBytes, fromBase64Url, isRecord, toBase64Url, WebAuthnError } from '@utils';

import type {
  AuthenticationExtensionsClientOutputs,
  AuthenticationResponseJSON,
  AuthenticatorAttachmentField,
  AuthenticatorTransport,
  BinarySource,
  CreationOptionsBinary,
  CredentialDescriptorBinary,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialLike,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  RequestOptionsBinary,
} from '@types';

/** Realm-safe ArrayBuffer check (iframes / Electron contexts have distinct globals). */
const isArrayBuffer = (v: unknown): v is ArrayBuffer =>
  Object.prototype.toString.call(v) === '[object ArrayBuffer]';

const bin = (value: string): BinarySource => copyBytes(fromBase64Url(value));
const b64 = (buffer: ArrayBuffer): string => toBase64Url(new Uint8Array(buffer));

const descriptors = (
  list?: readonly PublicKeyCredentialDescriptorJSON[],
): CredentialDescriptorBinary[] =>
  (list ?? []).map((d) => ({
    type: 'public-key',
    id: bin(d.id),
    ...(d.transports ? { transports: [...d.transports] } : {}),
  }));

/** JSON → binary options. Manual (not parseCreationOptionsFromJSON) for identical behaviour everywhere. */
export function toCreationOptions(
  json: PublicKeyCredentialCreationOptionsJSON,
): CreationOptionsBinary {
  if (!isRecord(json) || !isRecord(json.user) || !isRecord(json.rp)) {
    throw new WebAuthnError(
      'INVALID_INPUT',
      'Invalid PublicKeyCredentialCreationOptionsJSON',
    );
  }
  return {
    rp: { ...json.rp },
    user: {
      id: bin(json.user.id),
      name: json.user.name,
      displayName: json.user.displayName,
    },
    challenge: bin(json.challenge),
    pubKeyCredParams: json.pubKeyCredParams.map((p) => ({
      type: 'public-key',
      alg: p.alg,
    })),
    ...(json.timeout === undefined ? {} : { timeout: json.timeout }),
    ...(json.excludeCredentials
      ? { excludeCredentials: descriptors(json.excludeCredentials) }
      : {}),
    ...(json.authenticatorSelection
      ? { authenticatorSelection: { ...json.authenticatorSelection } }
      : {}),
    ...(json.hints ? { hints: [...json.hints] } : {}),
    ...(json.attestation ? { attestation: json.attestation } : {}),
    ...(json.attestationFormats
      ? { attestationFormats: [...json.attestationFormats] }
      : {}),
    ...(json.extensions ? { extensions: { ...json.extensions } } : {}),
  };
}

export function toRequestOptions(
  json: PublicKeyCredentialRequestOptionsJSON,
): RequestOptionsBinary {
  if (!isRecord(json))
    throw new WebAuthnError(
      'INVALID_INPUT',
      'Invalid PublicKeyCredentialRequestOptionsJSON',
    );
  return {
    challenge: bin(json.challenge),
    ...(json.timeout === undefined ? {} : { timeout: json.timeout }),
    ...(json.rpId ? { rpId: json.rpId } : {}),
    ...(json.allowCredentials
      ? { allowCredentials: descriptors(json.allowCredentials) }
      : {}),
    ...(json.userVerification ? { userVerification: json.userVerification } : {}),
    ...(json.hints ? { hints: [...json.hints] } : {}),
    ...(json.extensions ? { extensions: { ...json.extensions } } : {}),
  };
}

/** Recursively base64url-encode binary values in extension outputs (prf, largeBlob…). */
function jsonifyExtensions(value: unknown, depth = 0): unknown {
  if (depth > 8) return undefined;
  if (isArrayBuffer(value)) return b64(value);
  if (ArrayBuffer.isView(value)) {
    return toBase64Url(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
  }
  if (Array.isArray(value)) return value.map((v) => jsonifyExtensions(v, depth + 1));
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, jsonifyExtensions(v, depth + 1)]),
    );
  }
  return value;
}

const attachment = (value: unknown): AuthenticatorAttachmentField =>
  value === 'platform' || value === 'cross-platform'
    ? { authenticatorAttachment: value }
    : {};

function assertCredential(value: unknown): asserts value is PublicKeyCredentialLike {
  if (!isRecord(value) || !isArrayBuffer(value.rawId) || !isRecord(value.response)) {
    throw new WebAuthnError(
      'UNKNOWN_ERROR',
      'Authenticator returned an unexpected credential',
    );
  }
}

const safeCall = <T>(fn: (() => T) | undefined): T | undefined => {
  try {
    return fn?.();
  } catch {
    // Some password-manager extensions throw from these getters.
    return undefined;
  }
};

export function registrationToJSON(value: unknown): RegistrationResponseJSON {
  assertCredential(value);
  const r = value.response;
  if (!isArrayBuffer(r.attestationObject)) {
    throw new WebAuthnError(
      'UNKNOWN_ERROR',
      'Missing attestationObject in registration response',
    );
  }
  const transports = safeCall(r.getTransports?.bind(r));
  const alg = safeCall(r.getPublicKeyAlgorithm?.bind(r));
  const publicKey = safeCall(r.getPublicKey?.bind(r));
  const authData = safeCall(r.getAuthenticatorData?.bind(r));
  return {
    id: value.id,
    rawId: b64(value.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: b64(r.clientDataJSON),
      attestationObject: b64(r.attestationObject),
      ...(authData ? { authenticatorData: b64(authData) } : {}),
      ...(transports ? { transports: transports as AuthenticatorTransport[] } : {}),
      ...(typeof alg === 'number' ? { publicKeyAlgorithm: alg } : {}),
      ...(publicKey ? { publicKey: b64(publicKey) } : {}),
    },
    ...attachment(value.authenticatorAttachment),
    clientExtensionResults: jsonifyExtensions(
      safeCall(value.getClientExtensionResults.bind(value)) ?? {},
    ) as AuthenticationExtensionsClientOutputs,
  };
}

export function authenticationToJSON(value: unknown): AuthenticationResponseJSON {
  assertCredential(value);
  const r = value.response;
  if (!isArrayBuffer(r.authenticatorData) || !isArrayBuffer(r.signature)) {
    throw new WebAuthnError(
      'UNKNOWN_ERROR',
      'Missing assertion fields in authentication response',
    );
  }
  return {
    id: value.id,
    rawId: b64(value.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: b64(r.clientDataJSON),
      authenticatorData: b64(r.authenticatorData),
      signature: b64(r.signature),
      ...(isArrayBuffer(r.userHandle) && r.userHandle.byteLength > 0
        ? { userHandle: b64(r.userHandle) }
        : {}),
    },
    ...attachment(value.authenticatorAttachment),
    clientExtensionResults: jsonifyExtensions(
      safeCall(value.getClientExtensionResults.bind(value)) ?? {},
    ) as AuthenticationExtensionsClientOutputs,
  };
}

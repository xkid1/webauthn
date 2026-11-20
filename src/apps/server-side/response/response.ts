import {
  fromBase64Url,
  isBase64Url,
  isRecord,
  timingSafeEqual,
  WebAuthnError,
} from '@utils';

import type {
  AuthenticationResponseJSON,
  AuthenticatorTransport,
  CredentialDescriptorInput,
  PublicKeyCredentialDescriptorJSON,
  RegistrationResponseJSON,
} from '@types';

const TRANSPORTS: ReadonlySet<string> = new Set<AuthenticatorTransport>([
  'ble',
  'cable',
  'hybrid',
  'internal',
  'nfc',
  'smart-card',
  'usb',
]);

/** Drop unknown transport strings (never trust client-supplied enums). */
export const sanitizeTransports = (value: unknown): AuthenticatorTransport[] =>
  Array.isArray(value)
    ? [
        ...new Set(
          value.filter(
            (t): t is AuthenticatorTransport =>
              typeof t === 'string' && TRANSPORTS.has(t),
          ),
        ),
      ]
    : [];

const invalid = (message: string): never => {
  throw new WebAuthnError('INVALID_INPUT', message);
};

const requireB64 = (value: unknown, field: string): string =>
  isBase64Url(value) && value.length > 0
    ? value
    : invalid(`"${field}" must be a base64url string`);

function assertCommon(response: unknown): Record<string, unknown> {
  if (!isRecord(response)) return invalid('Credential response must be an object');
  const id = requireB64(response.id, 'id');
  const rawId = requireB64(response.rawId, 'rawId');
  if (response.type !== 'public-key') invalid('"type" must be "public-key"');
  if (!timingSafeEqual(fromBase64Url(id), fromBase64Url(rawId))) {
    throw new WebAuthnError('CREDENTIAL_ID_MISMATCH', '"id" and "rawId" differ');
  }
  if (!isRecord(response.response)) invalid('"response" must be an object');
  return response.response as Record<string, unknown>;
}

/** Structural validation of untrusted JSON from the client. */
export function assertRegistrationResponse(
  value: unknown,
): asserts value is RegistrationResponseJSON {
  const r = assertCommon(value);
  requireB64(r.clientDataJSON, 'response.clientDataJSON');
  requireB64(r.attestationObject, 'response.attestationObject');
}

export function assertAuthenticationResponse(
  value: unknown,
): asserts value is AuthenticationResponseJSON {
  const r = assertCommon(value);
  requireB64(r.clientDataJSON, 'response.clientDataJSON');
  requireB64(r.authenticatorData, 'response.authenticatorData');
  requireB64(r.signature, 'response.signature');
  if (r.userHandle !== undefined && r.userHandle !== null && !isBase64Url(r.userHandle)) {
    invalid('"response.userHandle" must be base64url');
  }
}

export function toDescriptors(
  credentials: readonly CredentialDescriptorInput[] | undefined,
): PublicKeyCredentialDescriptorJSON[] {
  return (credentials ?? []).map(({ id, transports }) => {
    requireB64(id, 'credential.id');
    const clean = sanitizeTransports(transports);
    return { type: 'public-key', id, ...(clean.length > 0 ? { transports: clean } : {}) };
  });
}

import { fromBase64Url, isRecord, toBase64Url, WebAuthnError } from '@utils';

import type {
  AndroidCredentialBridge,
  AndroidPasskeyClient,
  AuthenticationResponseJSON,
  AuthenticatorAttachmentField,
  AuthenticatorTransport,
  RegistrationResponseJSON,
  WebAuthnErrorCode,
} from '@types';

/** Re-encode to canonical unpadded base64url (some bridges emit padded / standard base64). */
const canon = (value: unknown, field: string): string => {
  if (typeof value !== 'string' || value.length === 0) {
    throw new WebAuthnError('INVALID_INPUT', `Android response is missing "${field}"`);
  }
  return toBase64Url(fromBase64Url(value, { lenient: true }));
};

const optionalCanon = (value: unknown, field: string): string | undefined =>
  value === undefined || value === null || value === '' ? undefined : canon(value, field);

function parsePayload(payload: string | object): Record<string, unknown> {
  let value: unknown = payload;
  if (typeof payload === 'string') {
    try {
      value = JSON.parse(payload);
    } catch (cause) {
      throw new WebAuthnError('INVALID_INPUT', 'Android bridge returned invalid JSON', {
        cause,
      });
    }
  }
  if (!isRecord(value) || !isRecord(value.response)) {
    throw new WebAuthnError(
      'INVALID_INPUT',
      'Android bridge returned an unexpected credential',
    );
  }
  return value;
}

const attachment = (v: unknown): AuthenticatorAttachmentField =>
  v === 'platform' || v === 'cross-platform' ? { authenticatorAttachment: v } : {};

const extensions = (v: unknown): Record<string, unknown> => (isRecord(v) ? v : {});

function common(raw: Record<string, unknown>) {
  const rawId = canon(raw.rawId ?? raw.id, 'rawId');
  const id = canon(raw.id ?? raw.rawId, 'id');
  if (id !== rawId)
    throw new WebAuthnError('CREDENTIAL_ID_MISMATCH', 'Android response id/rawId differ');
  return { id, rawId, type: 'public-key' as const };
}

export function normaliseRegistration(
  payload: string | object,
): RegistrationResponseJSON {
  const raw = parsePayload(payload);
  const r = raw.response as Record<string, unknown>;
  const authenticatorData = optionalCanon(r.authenticatorData, 'authenticatorData');
  const publicKey = optionalCanon(r.publicKey, 'publicKey');
  return {
    ...common(raw),
    response: {
      clientDataJSON: canon(r.clientDataJSON, 'clientDataJSON'),
      attestationObject: canon(r.attestationObject, 'attestationObject'),
      ...(authenticatorData ? { authenticatorData } : {}),
      ...(publicKey ? { publicKey } : {}),
      ...(typeof r.publicKeyAlgorithm === 'number'
        ? { publicKeyAlgorithm: r.publicKeyAlgorithm }
        : {}),
      ...(Array.isArray(r.transports)
        ? {
            transports: r.transports.filter(
              (t) => typeof t === 'string',
            ) as AuthenticatorTransport[],
          }
        : {}),
    },
    ...attachment(raw.authenticatorAttachment),
    clientExtensionResults: extensions(raw.clientExtensionResults),
  };
}

export function normaliseAuthentication(
  payload: string | object,
): AuthenticationResponseJSON {
  const raw = parsePayload(payload);
  const r = raw.response as Record<string, unknown>;
  const userHandle = optionalCanon(r.userHandle, 'userHandle');
  return {
    ...common(raw),
    response: {
      clientDataJSON: canon(r.clientDataJSON, 'clientDataJSON'),
      authenticatorData: canon(r.authenticatorData, 'authenticatorData'),
      signature: canon(r.signature, 'signature'),
      ...(userHandle ? { userHandle } : {}),
    },
    ...attachment(raw.authenticatorAttachment),
    clientExtensionResults: extensions(raw.clientExtensionResults),
  };
}

/** Map androidx.credentials exception types (as surfaced by the bridge) to stable codes. */
const PATTERNS: readonly [RegExp, WebAuthnErrorCode][] = [
  [/InvalidStateError|EXCLUDE|already registered/iu, 'CREDENTIAL_EXCLUDED'],
  [/Cancellation|cancel+ed|USER_CANCELED/iu, 'CEREMONY_NOT_ALLOWED'],
  [/NoCredential|NotAllowedError/iu, 'CEREMONY_NOT_ALLOWED'],
  [/Interrupted|AbortError/iu, 'CEREMONY_ABORTED'],
  [/Unsupported|NotSupportedError|ProviderConfiguration/iu, 'NOT_SUPPORTED'],
  [/SecurityError|assetlinks|DOMAIN|RP ID|rpId/iu, 'SECURITY_ERROR'],
  [/ConstraintError/iu, 'CONSTRAINT_ERROR'],
];

export function toAndroidError(error: unknown): WebAuthnError {
  if (error instanceof WebAuthnError) return error;
  const parts = isRecord(error)
    ? [error.code, error.name, error.type, error.message].filter(
        (p): p is string => typeof p === 'string',
      )
    : [String(error)];
  const text = parts.join(' ');
  const code = PATTERNS.find(([re]) => re.test(text))?.[1] ?? 'UNKNOWN_ERROR';
  return new WebAuthnError(
    code,
    text.length > 0
      ? `Android Credential Manager: ${text}`
      : 'Android Credential Manager error',
    { cause: error },
  );
}

export function createAndroidPasskeyClient(
  bridge: AndroidCredentialBridge,
): AndroidPasskeyClient {
  if (
    typeof bridge.createCredential !== 'function' ||
    typeof bridge.getCredential !== 'function'
  ) {
    throw new WebAuthnError(
      'INVALID_CONFIG',
      'Android bridge must implement createCredential and getCredential',
    );
  }
  return {
    async isAvailable() {
      try {
        return (await bridge.isAvailable?.()) ?? true;
      } catch {
        return false;
      }
    },
    async startRegistration({ optionsJSON }) {
      try {
        return normaliseRegistration(
          await bridge.createCredential(JSON.stringify(optionsJSON)),
        );
      } catch (error) {
        throw toAndroidError(error);
      }
    },
    async startAuthentication({ optionsJSON }) {
      try {
        return normaliseAuthentication(
          await bridge.getCredential(JSON.stringify(optionsJSON)),
        );
      } catch (error) {
        throw toAndroidError(error);
      }
    },
  };
}

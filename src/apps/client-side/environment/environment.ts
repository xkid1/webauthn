import { WebAuthnError } from '@utils';

import type {
  AbortControllerLike,
  BrowserGlobals,
  CredentialsContainerLike,
  PublicKeyCredentialStatic,
} from '@types';

const g = (): BrowserGlobals => globalThis as unknown as BrowserGlobals;

export const getPublicKeyCredential = (): PublicKeyCredentialStatic | undefined =>
  g().PublicKeyCredential;

export function getCredentialsContainer(): CredentialsContainerLike {
  const credentials = g().navigator?.credentials;
  if (
    !getPublicKeyCredential() ||
    typeof credentials?.create !== 'function' ||
    typeof credentials.get !== 'function'
  ) {
    throw new WebAuthnError(
      'NOT_SUPPORTED',
      'WebAuthn is not available in this environment (requires a secure context: https or localhost). On React Native use @xkid1/webauthn/android.',
    );
  }
  return credentials as CredentialsContainerLike;
}

export const createAbortController = (): AbortControllerLike | undefined => {
  const Ctor = g().AbortController;
  return Ctor ? new Ctor() : undefined;
};

/** Number of `<input autocomplete="… webauthn">` elements (for conditional UI). */
export const countWebAuthnInputs = (): number =>
  g().document?.querySelectorAll(
    "input[autocomplete$='webauthn'], textarea[autocomplete$='webauthn']",
  ).length ?? 0;

export const isSecureContext = (): boolean => g().isSecureContext !== false;

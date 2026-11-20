import { getPublicKeyCredential, isSecureContext } from '../environment/index.js';

import type { Base64URLString, BrowserGlobals, ClientCapabilities } from '@types';

/** Synchronous: is the WebAuthn API present in a secure context? SSR-safe (false on the server). */
export function isWebAuthnSupported(): boolean {
  const pkc = getPublicKeyCredential();
  const nav = (globalThis as unknown as BrowserGlobals).navigator;
  return (
    pkc !== undefined &&
    typeof nav?.credentials?.create === 'function' &&
    isSecureContext()
  );
}

/** Is a user-verifying platform authenticator (Touch ID, Windows Hello, Android biometrics) available? */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  try {
    return (
      (await getPublicKeyCredential()?.isUserVerifyingPlatformAuthenticatorAvailable?.()) ??
      false
    );
  } catch {
    return false;
  }
}

/** Is passkey autofill (conditional mediation) available? */
export async function isConditionalMediationAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  try {
    return (await getPublicKeyCredential()?.isConditionalMediationAvailable?.()) ?? false;
  } catch {
    return false;
  }
}

/**
 * Feature detection via WebAuthn L3 `getClientCapabilities()` with graceful
 * fallbacks for browsers that do not implement it yet.
 */
export async function getClientCapabilities(): Promise<ClientCapabilities> {
  const webauthn = isWebAuthnSupported();
  let raw: Record<string, boolean> = {};
  if (webauthn) {
    try {
      raw = (await getPublicKeyCredential()?.getClientCapabilities?.()) ?? {};
    } catch {
      raw = {};
    }
  }
  const platformAuthenticator =
    raw.userVerifyingPlatformAuthenticator ?? (await isPlatformAuthenticatorAvailable());
  const conditionalGet = raw.conditionalGet ?? (await isConditionalMediationAvailable());
  return {
    webauthn,
    platformAuthenticator,
    conditionalGet,
    conditionalCreate: raw.conditionalCreate ?? false,
    hybridTransport: raw.hybridTransport ?? false,
    passkeyPlatformAuthenticator:
      raw.passkeyPlatformAuthenticator ?? platformAuthenticator,
    raw: Object.freeze({ ...raw }),
  };
}

/**
 * WebAuthn L3 Signal API – keep the user's password manager in sync with your
 * server. All calls are no-ops where unsupported and never throw.
 */
export const signals = {
  /** A credential was rejected because the server no longer knows it. */
  async unknownCredential(rpId: string, credentialId: Base64URLString): Promise<boolean> {
    return run(() =>
      getPublicKeyCredential()?.signalUnknownCredential?.({ rpId, credentialId }),
    );
  },
  /** Report the full list of valid credential IDs for a user (after sign-in). */
  async allAcceptedCredentials(
    rpId: string,
    userId: Base64URLString,
    ids: readonly Base64URLString[],
  ): Promise<boolean> {
    return run(() =>
      getPublicKeyCredential()?.signalAllAcceptedCredentials?.({
        rpId,
        userId,
        allAcceptedCredentialIds: [...ids],
      }),
    );
  },
  /** Update the name / display name shown by password managers. */
  async currentUserDetails(
    rpId: string,
    userId: Base64URLString,
    name: string,
    displayName: string,
  ): Promise<boolean> {
    return run(() =>
      getPublicKeyCredential()?.signalCurrentUserDetails?.({
        rpId,
        userId,
        name,
        displayName,
      }),
    );
  },
};

async function run(fn: () => Promise<void> | undefined): Promise<boolean> {
  try {
    const result = fn();
    if (!result) return false;
    await result;
    return true;
  } catch {
    return false;
  }
}

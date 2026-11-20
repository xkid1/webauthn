/**
 * A fake browser (navigator.credentials, PublicKeyCredential, isSecureContext)
 * backed by the SoftAuthenticator, for client-side tests. Call
 * `vi.unstubAllGlobals()` in afterEach.
 */
import { vi } from 'vitest';

import { fromBase64Url, toBase64Url } from '@utils';

import type { SoftAuthenticator } from './authenticator.js';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@types';

const ab = (b64: string): ArrayBuffer => fromBase64Url(b64).slice().buffer;
const b64 = (v: Uint8Array | ArrayBuffer) =>
  toBase64Url(v instanceof Uint8Array ? v : new Uint8Array(v));

export type AnyRecord = Record<string, unknown>;

function toBrowserRegistration(json: RegistrationResponseJSON) {
  return {
    id: json.id,
    rawId: ab(json.rawId),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: ab(json.response.clientDataJSON),
      attestationObject: ab(json.response.attestationObject),
      getTransports: () => ['internal'],
      getPublicKeyAlgorithm: () => json.response.publicKeyAlgorithm,
      getPublicKey: () => {
        throw new Error('extension bug');
      },
    },
    getClientExtensionResults: () => ({
      credProps: { rk: true },
      prf: { results: { first: new Uint8Array([1, 2]).buffer } },
    }),
  };
}

function toBrowserAssertion(json: AuthenticationResponseJSON) {
  return {
    id: json.id,
    rawId: ab(json.rawId),
    type: 'public-key',
    authenticatorAttachment: 'cross-platform',
    response: {
      clientDataJSON: ab(json.response.clientDataJSON),
      authenticatorData: ab(json.response.authenticatorData),
      signature: ab(json.response.signature),
      userHandle: json.response.userHandle ? ab(json.response.userHandle) : null,
    },
    getClientExtensionResults: () => ({}),
  };
}

export function installBrowser(
  auth: SoftAuthenticator,
  overrides: Partial<{ create: unknown; get: unknown }> = {},
) {
  const create = vi.fn(async ({ publicKey }: { publicKey: AnyRecord }) => {
    const pk = publicKey as unknown as {
      challenge: Uint8Array;
      user: { id: Uint8Array; name: string; displayName: string };
    } & AnyRecord;
    const json = {
      ...publicKey,
      challenge: b64(pk.challenge),
      user: { ...pk.user, id: b64(pk.user.id) },
    } as unknown as PublicKeyCredentialCreationOptionsJSON;
    return toBrowserRegistration(await auth.register(json));
  });
  const get = vi.fn(async ({ publicKey }: { publicKey: AnyRecord }) => {
    const json = {
      ...publicKey,
      challenge: b64(publicKey.challenge as Uint8Array),
    } as unknown as PublicKeyCredentialRequestOptionsJSON;
    return toBrowserAssertion(await auth.authenticate(json));
  });
  vi.stubGlobal('navigator', {
    credentials: { create: overrides.create ?? create, get: overrides.get ?? get },
  });
  vi.stubGlobal('PublicKeyCredential', {
    isUserVerifyingPlatformAuthenticatorAvailable: () => Promise.resolve(true),
    isConditionalMediationAvailable: () => Promise.resolve(true),
    signalUnknownCredential: vi.fn(() => Promise.resolve()),
  });
  vi.stubGlobal('isSecureContext', true);
  return { create, get };
}

/** A DOMException-like error with the given `name`. */
export const domError = (name: string) => Object.assign(new Error(name), { name });

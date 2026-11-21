import { WebAuthnError } from '../error';

import type { CryptoGlobal, CryptoLike } from '@types';

/**
 * Resolve a WebCrypto implementation. Order: explicit injection → globalThis.crypto.
 * Node ≥ 20, all evergreen browsers, Electron and Deno expose globalThis.crypto.
 * React Native needs a WebCrypto polyfill only if you run *server* verification on-device
 * (you normally should not).
 */
export function resolveCrypto(injected?: CryptoLike): CryptoLike {
  if (injected) return injected;
  const candidate = (globalThis as unknown as CryptoGlobal).crypto;
  if (candidate?.subtle && typeof candidate.getRandomValues === 'function') {
    return candidate as CryptoLike;
  }
  throw new WebAuthnError(
    'UNSUPPORTED_ENVIRONMENT',
    'WebCrypto is unavailable. Pass `crypto` in the config (e.g. the `webcrypto` export of node:crypto).',
  );
}

/** Cryptographically secure random bytes. Never falls back to Math.random. */
export function randomBytes(length: number, crypto?: CryptoLike): Uint8Array {
  if (!Number.isInteger(length) || length <= 0 || length > 65536) {
    throw new WebAuthnError(
      'INVALID_INPUT',
      'randomBytes length must be an integer in 1..65536',
    );
  }
  return resolveCrypto(crypto).getRandomValues(new Uint8Array(length));
}

export async function sha256(data: Uint8Array, crypto?: CryptoLike): Promise<Uint8Array> {
  return new Uint8Array(await resolveCrypto(crypto).subtle.digest('SHA-256', data));
}

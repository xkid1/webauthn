import { describe, expect, it } from 'vitest';

import { toHex } from '../bytes';
import { WebAuthnError } from '../error';
import { utf8Encode } from '../utf8';

import { randomBytes, resolveCrypto, sha256 } from './crypto';

import type { CryptoLike } from '@types';

describe('crypto', () => {
  it('randomBytes validates length', () => {
    expect(randomBytes(32)).toHaveLength(32);
    expect(() => randomBytes(0)).toThrow(WebAuthnError);
    expect(() => randomBytes(65537)).toThrow(WebAuthnError);
  });

  it('sha256 matches the FIPS 180-2 "abc" vector', async () => {
    expect(toHex(await sha256(utf8Encode('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('prefers an injected implementation', () => {
    const injected = {
      subtle: {},
      getRandomValues: (a: Uint8Array) => a,
    } as unknown as CryptoLike;
    expect(resolveCrypto(injected)).toBe(injected);
  });
});

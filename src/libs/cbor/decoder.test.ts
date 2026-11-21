import { describe, expect, it } from 'vitest';

import { concatBytes, WebAuthnError } from '@utils';

import { decodeCbor, decodeCborFirst } from './decoder';

describe('decodeCbor', () => {
  it('rejects indefinite lengths, tags, duplicates and trailing bytes', () => {
    expect(() => decodeCbor(Uint8Array.of(0x9f, 0xff))).toThrow(/indefinite/u);
    expect(() => decodeCbor(Uint8Array.of(0xc0, 0x00))).toThrow(/tags/u);
    expect(() => decodeCbor(Uint8Array.of(0xa2, 0x01, 0x00, 0x01, 0x00))).toThrow(
      /duplicate/u,
    );
    expect(() => decodeCbor(Uint8Array.of(0x00, 0x00))).toThrow(/trailing/u);
    expect(decodeCborFirst(Uint8Array.of(0x00, 0x00)).length).toBe(1);
  });

  it('refuses length bombs and deep nesting', () => {
    // byte string claiming 4 GiB
    expect(() => decodeCbor(Uint8Array.of(0x5a, 0xff, 0xff, 0xff, 0xff))).toThrow(
      WebAuthnError,
    );
    // array claiming 2^32 items
    expect(() => decodeCbor(Uint8Array.of(0x9a, 0xff, 0xff, 0xff, 0xff))).toThrow(
      WebAuthnError,
    );
    const deep = new Uint8Array(40).fill(0x81);
    expect(() => decodeCbor(concatBytes(deep, Uint8Array.of(0)))).toThrow(/depth/u);
  });
});

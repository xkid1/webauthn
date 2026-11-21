import { webcrypto } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { WebAuthnError } from '@utils';

import { derToRawSignature, rawToDerSignature } from './ecdsa';

describe('ECDSA DER', () => {
  it('converts raw <-> DER for P-256 / P-521 sizes', () => {
    for (const size of [32, 66]) {
      const raw = webcrypto.getRandomValues(new Uint8Array(size * 2));
      raw[0] = 0x80; // force a leading-zero pad on r
      raw[size] = 0x00; // force s to be shorter
      expect(derToRawSignature(rawToDerSignature(raw), size)).toEqual(raw);
    }
  });

  it('rejects malformed DER', () => {
    expect(() => derToRawSignature(Uint8Array.of(0x31, 0x00), 32)).toThrow(WebAuthnError);
    expect(() =>
      derToRawSignature(
        Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00),
        32,
      ),
    ).toThrow(WebAuthnError);
  });
});

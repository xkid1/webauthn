import { describe, expect, it } from 'vitest';

import { WebAuthnError } from '../error';

import { utf8Decode, utf8Encode } from './utf8';

describe('utf8', () => {
  it('round-trips multilingual text and emoji', () => {
    const text = 'héllo — 你好 — 🔐';
    expect(utf8Decode(utf8Encode(text))).toBe(text);
  });

  it('encodes to the expected bytes', () => {
    expect(utf8Encode('€')).toEqual(Uint8Array.of(0xe2, 0x82, 0xac));
    expect(utf8Encode('🔐')).toEqual(Uint8Array.of(0xf0, 0x9f, 0x94, 0x90));
  });

  it('rejects malformed sequences', () => {
    expect(() => utf8Decode(Uint8Array.of(0xc0, 0x80))).toThrow(WebAuthnError); // overlong
    expect(() => utf8Decode(Uint8Array.of(0xed, 0xa0, 0x80))).toThrow(WebAuthnError); // surrogate
    expect(() => utf8Decode(Uint8Array.of(0xe2, 0x82))).toThrow(WebAuthnError); // truncated
  });
});

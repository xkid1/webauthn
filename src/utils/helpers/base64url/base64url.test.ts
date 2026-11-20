import { describe, expect, it } from 'vitest';

import { randomBytes } from '../crypto/index.js';
import { WebAuthnError } from '../error/index.js';
import { utf8Encode } from '../utf8/index.js';

import { fromBase64Url, isBase64Url, toBase64Url, toBytes } from './base64url.js';

describe('base64url', () => {
  it('round-trips every length 0..64', () => {
    for (let n = 0; n <= 64; n += 1) {
      const bytes = randomBytes(Math.max(n, 1)).subarray(0, n);
      const encoded = toBase64Url(bytes);
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/u);
      expect(fromBase64Url(encoded)).toEqual(bytes);
    }
  });

  it('matches RFC 4648 vectors', () => {
    expect(toBase64Url(utf8Encode('foobar'))).toBe('Zm9vYmFy');
    expect(toBase64Url(utf8Encode('fo'))).toBe('Zm8');
    expect(toBase64Url(Uint8Array.of(0xfb, 0xff))).toBe('-_8');
  });

  it('rejects invalid characters, lengths and non-canonical bits', () => {
    expect(() => fromBase64Url('ab+c')).toThrow(WebAuthnError);
    expect(() => fromBase64Url('abc=')).toThrow(WebAuthnError);
    expect(() => fromBase64Url('a')).toThrow(WebAuthnError);
    expect(() => fromBase64Url('Zm9=')).toThrow(WebAuthnError);
    expect(() => fromBase64Url('Zm8')).not.toThrow();
    expect(() => fromBase64Url('Zm9')).toThrow(/Non-canonical/u);
    expect(() => fromBase64Url('Zm-')).toThrow(/Non-canonical/u);
    expect(() => fromBase64Url(42 as unknown as string)).toThrow(
      expect.objectContaining({ code: 'ENCODING_ERROR' }) as Error,
    );
  });

  it('accepts standard base64 only in lenient mode', () => {
    expect(fromBase64Url('+/8=', { lenient: true })).toEqual(Uint8Array.of(0xfb, 0xff));
  });

  it('isBase64Url and toBytes', () => {
    expect(isBase64Url('Zm9v')).toBe(true);
    expect(isBase64Url('Zm9v=')).toBe(false);
    expect(isBase64Url('a')).toBe(false);
    expect(toBytes('Zm8')).toEqual(utf8Encode('fo'));
    const bytes = Uint8Array.of(1, 2);
    expect(toBytes(bytes)).toBe(bytes);
  });
});

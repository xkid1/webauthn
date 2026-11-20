import { describe, expect, it } from 'vitest';

import { WebAuthnError } from '../error/index.js';

import {
  bufferToBytes,
  concatBytes,
  copyBytes,
  formatUuid,
  fromHex,
  readUint16BE,
  readUint32BE,
  timingSafeEqual,
  toHex,
} from './bytes.js';

describe('bytes', () => {
  it('compares in constant time semantics', () => {
    expect(timingSafeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
    expect(timingSafeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(timingSafeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 0))).toBe(false);
  });

  it('hex + uuid', () => {
    expect(toHex(fromHex('DE:AD:be:ef'))).toBe('deadbeef');
    expect(() => fromHex('abc')).toThrow(WebAuthnError);
    expect(formatUuid(fromHex('00112233445566778899aabbccddeeff'))).toBe(
      '00112233-4455-6677-8899-aabbccddeeff',
    );
  });

  it('concatenates and copies into fresh buffers', () => {
    const a = Uint8Array.of(1, 2);
    expect(concatBytes(a, Uint8Array.of(3))).toEqual(Uint8Array.of(1, 2, 3));
    const view = new Uint8Array(Uint8Array.of(9, 1, 2, 9).buffer, 1, 2);
    const copy = copyBytes(view);
    expect(copy).toEqual(a);
    expect(copy.buffer.byteLength).toBe(2);
    expect(bufferToBytes(Uint8Array.of(5, 6).buffer)).toEqual(Uint8Array.of(5, 6));
  });

  it('reads big-endian integers', () => {
    const b = Uint8Array.of(0x01, 0x02, 0x03, 0x04);
    expect(readUint16BE(b, 1)).toBe(0x0203);
    expect(readUint32BE(b, 0)).toBe(0x01020304);
  });
});

import { describe, expect, it } from 'vitest';

import { readTlv } from './der.js';

describe('DER high-tag-number form', () => {
  const highTag = Uint8Array.of(0xbf, 0x85, 0x3e, 0x03, 0x02, 0x01, 0x00); // [702] { INTEGER 0 }

  it('is rejected by default and parsed only when allowed', () => {
    expect(() => readTlv(highTag, 0)).toThrow(
      expect.objectContaining({ code: 'ASN1_ERROR' }) as Error,
    );
    expect(readTlv(highTag, 0, highTag.length, true)).toMatchObject({
      tagNumber: 702,
      start: 4,
    });
  });

  it.each([
    ['non-minimal', Uint8Array.of(0xbf, 0x80, 0x85, 0x3e, 0x00)],
    ['low number in high form', Uint8Array.of(0xbf, 0x1e, 0x00)],
    ['truncated', Uint8Array.of(0xbf, 0x85)],
    ['too long', Uint8Array.of(0xbf, 0x81, 0x81, 0x81, 0x01, 0x00)],
  ])('rejects %s tags', (_label, bytes) => {
    expect(() => readTlv(bytes, 0, bytes.length, true)).toThrow(
      expect.objectContaining({ code: 'ASN1_ERROR' }) as Error,
    );
  });
});

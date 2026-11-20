import { WebAuthnError } from '../error/index.js';

/**
 * Self-contained UTF-8 codec. TextEncoder/TextDecoder are not guaranteed on
 * every React Native engine, so we do not rely on them.
 */

export function utf8Encode(input: string): Uint8Array {
  const out: number[] = [];
  for (const char of input) {
    const cp = char.codePointAt(0)!;
    if (cp >= 0xd800 && cp <= 0xdfff) {
      throw new WebAuthnError('ENCODING_ERROR', 'Lone surrogate in string');
    }
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000)
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 63),
        0x80 | ((cp >> 6) & 63),
        0x80 | (cp & 63),
      );
  }
  return Uint8Array.from(out);
}

/** Strict (fatal) decoder: rejects overlong forms, surrogates and truncation. */
export function utf8Decode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  const fail = (): never => {
    throw new WebAuthnError('ENCODING_ERROR', 'Invalid UTF-8 sequence');
  };
  const cont = (k: number): number => {
    const b = bytes[i + k];
    if (b === undefined || (b & 0xc0) !== 0x80) fail();
    return b! & 63;
  };
  while (i < bytes.length) {
    const b0 = bytes[i]!;
    let cp: number;
    if (b0 < 0x80) {
      cp = b0;
      i += 1;
    } else if (b0 >= 0xc2 && b0 <= 0xdf) {
      cp = ((b0 & 31) << 6) | cont(1);
      i += 2;
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      cp = ((b0 & 15) << 12) | (cont(1) << 6) | cont(2);
      if (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff)) fail();
      i += 3;
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      cp = ((b0 & 7) << 18) | (cont(1) << 12) | (cont(2) << 6) | cont(3);
      if (cp < 0x10000 || cp > 0x10ffff) fail();
      i += 4;
    } else {
      return fail();
    }
    out += String.fromCodePoint(cp);
  }
  return out;
}

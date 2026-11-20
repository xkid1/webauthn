import { utf8Decode, WebAuthnError } from '@utils';

import type { Tlv } from '@types';

/**
 * Strict ASN.1 DER reader – just enough for X.509 attestation certificates.
 * Only definite, minimally-encoded lengths up to 4 bytes are accepted.
 */

export const Tag = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  TELETEX_STRING: 0x14,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

const fail = (message: string): never => {
  throw new WebAuthnError('ASN1_ERROR', `DER: ${message}`);
};

const MAX_HIGH_TAG_OCTETS = 3;

/**
 * Read one TLV. High-tag-number form (tag ≥ 31) is rejected unless
 * `allowHighTag` is set – only the Android KeyDescription needs it.
 */
export function readTlv(
  bytes: Uint8Array,
  offset: number,
  limit = bytes.length,
  allowHighTag = false,
): Tlv {
  const tag = bytes[offset];
  if (tag === undefined || offset >= limit) return fail('unexpected end of input');
  let tagNumber = tag & 0x1f;
  let lengthOffset = offset + 1;
  if (tagNumber === 0x1f) {
    if (!allowHighTag) return fail('high-tag-number form not supported');
    tagNumber = 0;
    for (let i = 0; ; i += 1) {
      if (i >= MAX_HIGH_TAG_OCTETS) return fail('tag number too large');
      const b = bytes[lengthOffset];
      if (b === undefined || lengthOffset >= limit) return fail('truncated tag');
      if (i === 0 && b === 0x80) return fail('non-minimal tag');
      tagNumber = tagNumber * 128 + (b & 0x7f);
      lengthOffset += 1;
      if (!(b & 0x80)) break;
    }
    if (tagNumber < 0x1f) return fail('non-minimal tag');
  }
  const first = bytes[lengthOffset];
  if (first === undefined) return fail('missing length');
  let length = first;
  let start = lengthOffset + 1;
  if (first & 0x80) {
    const count = first & 0x7f;
    if (count === 0) return fail('indefinite length not allowed');
    if (count > 4) return fail('length too large');
    length = 0;
    for (let i = 0; i < count; i += 1) {
      const b = bytes[start + i];
      if (b === undefined) return fail('truncated length');
      if (i === 0 && b === 0) return fail('non-minimal length');
      length = length * 256 + b;
    }
    if (length < 0x80) return fail('non-minimal length');
    start += count;
  }
  const end = start + length;
  if (end > limit) return fail('content exceeds parent');
  return { tag, tagNumber, offset, start, end };
}

/** Read the children of a constructed TLV. */
export function readChildren(
  bytes: Uint8Array,
  parent: Tlv,
  allowHighTag = false,
): Tlv[] {
  const out: Tlv[] = [];
  let offset = parent.start;
  while (offset < parent.end) {
    const child = readTlv(bytes, offset, parent.end, allowHighTag);
    out.push(child);
    offset = child.end;
  }
  return out;
}

export function expectTag(tlv: Tlv | undefined, tag: number, what: string): Tlv {
  if (tlv?.tag !== tag) return fail(`expected ${what}`);
  return tlv;
}

export const content = (bytes: Uint8Array, tlv: Tlv): Uint8Array =>
  bytes.subarray(tlv.start, tlv.end);
export const whole = (bytes: Uint8Array, tlv: Tlv): Uint8Array =>
  bytes.subarray(tlv.offset, tlv.end);

export function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) return fail('empty OID');
  const parts: number[] = [];
  let value = 0;
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i]!;
    if (value === 0 && b === 0x80) return fail('non-minimal OID');
    value = value * 128 + (b & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER) return fail('OID arc too large');
    if (!(b & 0x80)) {
      if (parts.length === 0) {
        const first = value < 80 ? Math.floor(value / 40) : 2;
        parts.push(first, value - first * 40);
      } else {
        parts.push(value);
      }
      value = 0;
    } else if (i === bytes.length - 1) {
      return fail('truncated OID');
    }
  }
  return parts.join('.');
}

/** Non-negative DER INTEGER as a JS number (strict, minimal encoding, ≤ 2^53). */
export function decodeUnsignedInteger(bytes: Uint8Array, tlv: Tlv): number {
  const c = content(bytes, tlv);
  if (c.length === 0) return fail('empty INTEGER');
  if (c[0]! & 0x80) return fail('negative INTEGER');
  if (c.length > 1 && c[0] === 0 && !(c[1]! & 0x80)) return fail('non-minimal INTEGER');
  let value = 0;
  for (const b of c) {
    value = value * 256 + b;
    if (value > Number.MAX_SAFE_INTEGER) return fail('INTEGER too large');
  }
  return value;
}

/** BIT STRING content without the leading "unused bits" byte (must be 0). */
export function bitStringBytes(bytes: Uint8Array, tlv: Tlv): Uint8Array {
  const c = content(bytes, tlv);
  if (c[0] !== 0) return fail('BIT STRING with unused bits not supported');
  return c.subarray(1);
}

export function decodeString(bytes: Uint8Array, tlv: Tlv): string {
  const c = content(bytes, tlv);
  switch (tlv.tag) {
    case Tag.UTF8_STRING:
      return utf8Decode(c);
    case Tag.PRINTABLE_STRING:
    case Tag.IA5_STRING:
    case Tag.TELETEX_STRING:
      return String.fromCharCode(...c);
    default:
      return fail(`unsupported string tag 0x${tlv.tag.toString(16)}`);
  }
}

/** Decode UTCTime / GeneralizedTime (Zulu only) into epoch milliseconds. */
export function decodeTime(bytes: Uint8Array, tlv: Tlv): number {
  const s = String.fromCharCode(...content(bytes, tlv));
  let m: RegExpExecArray | null;
  let year: number;
  if (tlv.tag === Tag.UTC_TIME) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/u.exec(s);
    if (!m) return fail('bad UTCTime');
    const yy = Number(m[1]);
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
  } else if (tlv.tag === Tag.GENERALIZED_TIME) {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/u.exec(s);
    if (!m) return fail('bad GeneralizedTime');
    year = Number(m[1]);
  } else {
    return fail('expected time');
  }
  return Date.UTC(
    year,
    Number(m[2]) - 1,
    Number(m[3]),
    Number(m[4]),
    Number(m[5]),
    Number(m[6]),
  );
}

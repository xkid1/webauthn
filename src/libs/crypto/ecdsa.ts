import { concatBytes, WebAuthnError } from '@utils';

import type { DerIntegerRead } from '@types';

/**
 * ECDSA signature format conversion. Authenticators and X.509 use ASN.1 DER
 * (`SEQUENCE { INTEGER r, INTEGER s }`); WebCrypto expects raw `r || s`
 * (IEEE P1363). The parser is strict DER: minimal lengths, no trailing data.
 */

const bad = (message: string): never => {
  throw new WebAuthnError('SIGNATURE_INVALID', `ECDSA signature: ${message}`);
};

function readInteger(der: Uint8Array, offset: number, size: number): DerIntegerRead {
  if (der[offset] !== 0x02) bad('expected INTEGER');
  const len = der[offset + 1];
  if (len === undefined || len === 0 || len > 0x7f) bad('bad INTEGER length');
  const start = offset + 2;
  const end = start + len!;
  if (end > der.length) bad('truncated INTEGER');
  let value = der.subarray(start, end);
  if (value[0]! & 0x80) bad('negative INTEGER');
  if (value.length > 1 && value[0] === 0 && !(value[1]! & 0x80))
    bad('non-minimal INTEGER');
  if (value[0] === 0) value = value.subarray(1);
  if (value.length > size) bad('INTEGER too large for curve');
  const padded = new Uint8Array(size);
  padded.set(value, size - value.length);
  return { value: padded, next: end };
}

export function derToRawSignature(der: Uint8Array, size: number): Uint8Array {
  if (der[0] !== 0x30) bad('expected SEQUENCE');
  let offset = 2;
  let seqLen = der[1] ?? bad('truncated');
  if (seqLen === 0x81) {
    seqLen = der[2] ?? bad('truncated');
    if (seqLen < 0x80) bad('non-minimal length');
    offset = 3;
  } else if (seqLen > 0x80) {
    bad('bad SEQUENCE length');
  }
  if (offset + seqLen !== der.length) bad('length mismatch / trailing data');
  const r = readInteger(der, offset, size);
  const s = readInteger(der, r.next, size);
  if (s.next !== der.length) bad('trailing data');
  return concatBytes(r.value, s.value);
}

function encodeInteger(raw: Uint8Array): Uint8Array {
  let i = 0;
  while (i < raw.length - 1 && raw[i] === 0) i += 1;
  let v = raw.subarray(i);
  if (v[0]! & 0x80) v = concatBytes(Uint8Array.of(0), v);
  return concatBytes(Uint8Array.of(0x02, v.length), v);
}

export function rawToDerSignature(raw: Uint8Array): Uint8Array {
  if (raw.length % 2 !== 0) bad('raw signature length must be even');
  const half = raw.length / 2;
  const body = concatBytes(
    encodeInteger(raw.subarray(0, half)),
    encodeInteger(raw.subarray(half)),
  );
  const len =
    body.length < 0x80 ? Uint8Array.of(body.length) : Uint8Array.of(0x81, body.length);
  return concatBytes(Uint8Array.of(0x30), len, body);
}

import { concatBytes, utf8Encode, WebAuthnError } from '@utils';

import type { CborValue } from '@types';

/**
 * Minimal CTAP2-canonical CBOR encoder (definite lengths, shortest integer
 * form, map keys sorted length-first then bytewise). Used for test fixtures,
 * software authenticators and attestation tooling.
 */

function head(major: number, value: number | bigint): Uint8Array {
  const m = major << 5;
  const v = typeof value === 'bigint' ? value : BigInt(value);
  if (v < 24n) return Uint8Array.of(m | Number(v));
  if (v < 0x100n) return Uint8Array.of(m | 24, Number(v));
  if (v < 0x10000n) return Uint8Array.of(m | 25, Number(v >> 8n), Number(v & 0xffn));
  if (v < 0x100000000n) {
    const n = Number(v);
    return Uint8Array.of(
      m | 26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    );
  }
  const out = new Uint8Array(9);
  out[0] = m | 27;
  for (let i = 0; i < 8; i += 1) out[8 - i] = Number((v >> BigInt(i * 8)) & 0xffn);
  return out;
}

function compareKeys(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}

export function encodeCbor(value: CborValue): Uint8Array {
  if (value === false) return Uint8Array.of(0xf4);
  if (value === true) return Uint8Array.of(0xf5);
  if (value === null) return Uint8Array.of(0xf6);
  if (value === undefined) return Uint8Array.of(0xf7);
  if (typeof value === 'number' || typeof value === 'bigint') {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) {
      throw new WebAuthnError('CBOR_ERROR', 'CBOR encoder supports integers only');
    }
    const big = BigInt(value);
    return big >= 0n ? head(0, big) : head(1, -1n - big);
  }
  if (typeof value === 'string') {
    const bytes = utf8Encode(value);
    return concatBytes(head(3, bytes.length), bytes);
  }
  if (value instanceof Uint8Array) return concatBytes(head(2, value.length), value);
  if (Array.isArray(value))
    return concatBytes(head(4, value.length), ...value.map(encodeCbor));

  const entries = [...value.entries()]
    .map(([k, v]) => [encodeCbor(k), encodeCbor(v)] as const)
    .sort(([a], [b]) => compareKeys(a, b));
  return concatBytes(head(5, entries.length), ...entries.flat());
}

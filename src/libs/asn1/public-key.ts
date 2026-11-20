import { WebAuthnError } from '@utils';

import { bitStringBytes, content, expectTag, readChildren, readTlv, Tag } from './der.js';

import type { RsaPublicKey } from '@types';

/** Minimum RSA modulus size accepted anywhere (credential and certificate keys). */
export const MIN_RSA_BITS = 2048;

const fail = (message: string): never => {
  throw new WebAuthnError('ASN1_ERROR', `SubjectPublicKeyInfo: ${message}`);
};

export const stripLeadingZeros = (b: Uint8Array): Uint8Array => {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i += 1;
  return b.subarray(i);
};

/** Raw subjectPublicKey bits of a DER SubjectPublicKeyInfo. */
export function subjectPublicKey(spki: Uint8Array): Uint8Array {
  const outer = readTlv(spki, 0);
  if (outer.end !== spki.length) fail('trailing data');
  const [, key, extra] = readChildren(
    spki,
    expectTag(outer, Tag.SEQUENCE, 'SubjectPublicKeyInfo'),
  );
  if (extra) fail('unexpected field');
  return bitStringBytes(spki, expectTag(key, Tag.BIT_STRING, 'subjectPublicKey'));
}

/** RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } (leading zeros stripped). */
export function parseRsaPublicKey(spki: Uint8Array): RsaPublicKey {
  const key = subjectPublicKey(spki);
  const seq = readTlv(key, 0);
  if (seq.end !== key.length) fail('trailing data after RSAPublicKey');
  const [n, e, extra] = readChildren(key, expectTag(seq, Tag.SEQUENCE, 'RSAPublicKey'));
  if (extra) fail('unexpected RSAPublicKey field');
  return {
    n: stripLeadingZeros(content(key, expectTag(n, Tag.INTEGER, 'modulus'))),
    e: stripLeadingZeros(content(key, expectTag(e, Tag.INTEGER, 'exponent'))),
  };
}

/** Bit length of an RSA modulus. */
export function modulusBits(n: Uint8Array): number {
  const first = n[0] ?? 0;
  return first === 0 ? 0 : (n.length - 1) * 8 + (32 - Math.clz32(first));
}

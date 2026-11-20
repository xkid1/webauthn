/** Tiny DER writer used only to mint X.509 test certificates. */
import { webcrypto } from 'node:crypto';

import { rawToDerSignature } from '@libs';
import { concatBytes, copyBytes, utf8Encode } from '@utils';

type CryptoKeyPair = webcrypto.CryptoKeyPair;

const length = (n: number): Uint8Array => {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
};

export const tlv = (tag: number, ...content: Uint8Array[]): Uint8Array => {
  const body = concatBytes(...content);
  return concatBytes(Uint8Array.of(tag), length(body.length), body);
};

export const seq = (...c: Uint8Array[]) => tlv(0x30, ...c);
export const set = (...c: Uint8Array[]) => tlv(0x31, ...c);
export const explicit = (n: number, ...c: Uint8Array[]) => tlv(0xa0 + n, ...c);
/** EXPLICIT context-specific tag, using high-tag-number form when n ≥ 31. */
export const contextTag = (n: number, ...c: Uint8Array[]): Uint8Array => {
  if (n < 31) return explicit(n, ...c);
  const digits: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 128)) digits.unshift(v & 0x7f);
  for (let i = 0; i < digits.length - 1; i += 1) digits[i]! |= 0x80;
  const body = concatBytes(...c);
  return concatBytes(Uint8Array.of(0xbf, ...digits), length(body.length), body);
};
export const enumerated = (n: number) => tlv(0x0a, Uint8Array.of(n));
export const nullValue = () => tlv(0x05);
export const octet = (b: Uint8Array) => tlv(0x04, b);
export const bool = (v: boolean) => tlv(0x01, Uint8Array.of(v ? 0xff : 0));
export const utf8 = (s: string) => tlv(0x0c, utf8Encode(s));
export const bitString = (b: Uint8Array) => tlv(0x03, Uint8Array.of(0), b);
export const int = (n: number) => {
  const bytes: number[] = [];
  let v = n;
  do {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  } while (v > 0);
  if (bytes[0]! & 0x80) bytes.unshift(0);
  return tlv(0x02, Uint8Array.from(bytes));
};

export const oid = (dotted: string): Uint8Array => {
  const arcs = dotted.split('.').map(Number);
  const out: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const chunk: number[] = [];
    let v = arc;
    do {
      chunk.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i += 1) chunk[i]! |= 0x80;
    out.push(...chunk);
  }
  return tlv(0x06, Uint8Array.from(out));
};

const utcTime = (date: Date): Uint8Array => {
  const p = (n: number) => String(n).padStart(2, '0');
  const s = `${p(date.getUTCFullYear() % 100)}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
  return tlv(0x17, utf8Encode(s));
};

export const name = (attrs: readonly (readonly [string, string])[]) =>
  seq(...attrs.map(([o, v]) => set(seq(oid(o), utf8(v)))));

const ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const ECDSA_SHA384 = '1.2.840.10045.4.3.3';

export interface TestCertificate {
  der: Uint8Array;
  keyPair: CryptoKeyPair;
  subject: readonly (readonly [string, string])[];
}

export async function makeCertificate(options: {
  subject: readonly (readonly [string, string])[];
  issuer?: TestCertificate;
  ca?: boolean;
  aaguid?: Uint8Array;
  notBefore?: Date;
  notAfter?: Date;
  serial?: number;
  /** Certify this key pair (e.g. the credential key) instead of a fresh P-256 key. */
  keyPair?: CryptoKeyPair;
  /** Extra DER `Extension` SEQUENCEs. */
  extensions?: readonly Uint8Array[];
  /** Hash for the issuer's ECDSA signature (curve stays P-256). Default SHA-256. */
  signatureHash?: 'SHA-256' | 'SHA-384';
}): Promise<TestCertificate> {
  const keyPair =
    options.keyPair ??
    (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]));
  const spki = new Uint8Array(
    await webcrypto.subtle.exportKey('spki', keyPair.publicKey),
  );
  const extensions = [
    seq(oid('2.5.29.19'), bool(true), octet(seq(...(options.ca ? [bool(true)] : [])))),
  ];
  if (options.aaguid)
    extensions.push(seq(oid('1.3.6.1.4.1.45724.1.1.4'), octet(octet(options.aaguid))));
  extensions.push(...(options.extensions ?? []));

  const sigOid = options.signatureHash === 'SHA-384' ? ECDSA_SHA384 : ECDSA_SHA256;
  const tbs = seq(
    explicit(0, int(2)),
    int(options.serial ?? 1),
    seq(oid(sigOid)),
    name(options.issuer?.subject ?? options.subject),
    seq(
      utcTime(options.notBefore ?? new Date(Date.now() - 86_400_000)),
      utcTime(options.notAfter ?? new Date(Date.now() + 365 * 86_400_000)),
    ),
    name(options.subject),
    spki,
    explicit(3, seq(...extensions)),
  );
  const signer = options.issuer?.keyPair.privateKey ?? keyPair.privateKey;
  const raw = new Uint8Array(
    await webcrypto.subtle.sign(
      { name: 'ECDSA', hash: options.signatureHash ?? 'SHA-256' },
      signer,
      copyBytes(tbs),
    ),
  );
  const der = seq(tbs, seq(oid(sigOid)), bitString(rawToDerSignature(raw)));
  return { der, keyPair, subject: options.subject };
}

export const ATTESTATION_SUBJECT = [
  ['2.5.4.6', 'SG'],
  ['2.5.4.10', 'Test Vendor'],
  ['2.5.4.11', 'Authenticator Attestation'],
  ['2.5.4.3', 'Test Attestation Leaf'],
] as const;

export const ROOT_SUBJECT = [
  ['2.5.4.6', 'SG'],
  ['2.5.4.10', 'Test Vendor'],
  ['2.5.4.3', 'Test Root CA'],
] as const;

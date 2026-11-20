/**
 * Builders for "tpm", "android-key", "apple" and "android-safetynet" attestation
 * statements, signed with real keys. Plug them into `SoftAuthenticator.register`
 * through the `attest` hook. Each takes a `tamper` switch for negative tests.
 */
import { webcrypto } from 'node:crypto';

import { COSEAlgorithm } from '@libs';
import { concatBytes, copyBytes, fromBase64Url, toBase64Url, utf8Encode } from '@utils';

import {
  bool,
  contextTag,
  enumerated,
  int,
  makeCertificate,
  name,
  nullValue,
  octet,
  oid,
  seq,
  set,
  tlv,
  type TestCertificate,
} from './der.js';

import type { RegisterOverrides, SoftAuthenticator } from './authenticator.js';
import type { CborValue } from '@types';

type Attest = NonNullable<RegisterOverrides['attest']>;

const sha256 = async (data: Uint8Array) =>
  new Uint8Array(await webcrypto.subtle.digest('SHA-256', copyBytes(data)));

const flip = (b: Uint8Array): Uint8Array => {
  const c = b.slice();
  c[c.length - 1]! ^= 0x01;
  return c;
};

const toStdBase64 = (b: Uint8Array): string => {
  const s = toBase64Url(b).replace(/-/gu, '+').replace(/_/gu, '/');
  return s + '='.repeat((4 - (s.length % 4)) % 4);
};

const u16 = (n: number) => Uint8Array.of(n >> 8, n & 0xff);
const u32 = (n: number) =>
  Uint8Array.of(n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
const tpm2b = (b: Uint8Array) => concatBytes(u16(b.length), b);

// ---------------------------------------------------------------------------
// tpm
// ---------------------------------------------------------------------------

export type TpmTamper =
  | 'signature'
  | 'extraData'
  | 'name'
  | 'pubAreaKey'
  | 'magic'
  | 'type'
  | 'subject'
  | 'eku'
  | 'sanNotCritical'
  | 'sanAttrs'
  | 'manufacturer'
  | 'aikCa'
  | 'aaguid'
  | 'nameAlgSha1'
  | 'trailing'
  | 'keyBits'
  | 'rs1'
  | 'ver';

export const TPM_SAN_ATTRS = [
  ['2.23.133.2.1', 'id:414D4400'],
  ['2.23.133.2.2', 'SoftTPM'],
  ['2.23.133.2.3', 'id:00010000'],
] as const;

async function tpmUnique(
  authenticator: SoftAuthenticator,
  tamper: TpmTamper | undefined,
): Promise<Uint8Array> {
  const jwk = await webcrypto.subtle.exportKey('jwk', authenticator.keyPair.publicKey);
  if (authenticator.alg === COSEAlgorithm.RS256) {
    const n = fromBase64Url(jwk.n!);
    return concatBytes(
      u16(0x0010), // scheme NULL
      u16(tamper === 'keyBits' ? 1024 : n.length * 8),
      u32(0), // exponent 0 = default 65537
      tpm2b(tamper === 'pubAreaKey' ? flip(n) : n),
    );
  }
  const x = fromBase64Url(jwk.x!);
  return concatBytes(
    u16(0x0010), // scheme NULL
    u16(0x0003), // NIST P-256
    u16(0x0010), // kdf NULL
    tpm2b(tamper === 'pubAreaKey' ? flip(x) : x),
    tpm2b(fromBase64Url(jwk.y!)),
  );
}

export function tpmAttestation(root: TestCertificate, tamper?: TpmTamper): Attest {
  return async ({ authData, clientDataHash, authenticator }) => {
    const rsa = authenticator.alg === COSEAlgorithm.RS256;
    const nameAlg = tamper === 'nameAlgSha1' ? 0x0004 : 0x000b;
    const pubArea = concatBytes(
      u16(rsa ? 0x0001 : 0x0023), // TPM_ALG_RSA / TPM_ALG_ECC
      u16(nameAlg),
      u32(0x00060472), // objectAttributes
      tpm2b(new Uint8Array(0)), // authPolicy
      u16(0x0010), // symmetric NULL
      await tpmUnique(authenticator, tamper),
      tamper === 'trailing' ? Uint8Array.of(0) : new Uint8Array(0),
    );
    const extraData = await sha256(concatBytes(authData, clientDataHash));
    const nameHash = new Uint8Array(
      await webcrypto.subtle.digest(
        nameAlg === 0x0004 ? 'SHA-1' : 'SHA-256',
        copyBytes(pubArea),
      ),
    );
    const attestedName = concatBytes(u16(nameAlg), nameHash);
    const certInfo = concatBytes(
      u32(tamper === 'magic' ? 0xff544348 : 0xff544347),
      u16(tamper === 'type' ? 0x8014 : 0x8017),
      tpm2b(new Uint8Array(0)), // qualifiedSigner
      tpm2b(tamper === 'extraData' ? flip(extraData) : extraData),
      new Uint8Array(17), // clockInfo
      new Uint8Array(8), // firmwareVersion
      tpm2b(tamper === 'name' ? flip(attestedName) : attestedName),
      tpm2b(new Uint8Array(0)), // qualifiedName
    );

    const sanAttrs: readonly (readonly [string, string])[] =
      tamper === 'sanAttrs'
        ? TPM_SAN_ATTRS.slice(0, 2)
        : tamper === 'manufacturer'
          ? [['2.23.133.2.1', 'AMD'], ...TPM_SAN_ATTRS.slice(1)]
          : TPM_SAN_ATTRS;
    const aik = await makeCertificate({
      subject: tamper === 'subject' ? [['2.5.4.3', 'AIK']] : [],
      issuer: root,
      serial: 10,
      ca: tamper === 'aikCa',
      ...(tamper === 'aaguid' ? { aaguid: new Uint8Array(16).fill(7) } : {}),
      extensions: [
        seq(
          oid('2.5.29.17'),
          ...(tamper === 'sanNotCritical' ? [] : [bool(true)]),
          octet(seq(tlv(0xa4, name(sanAttrs)))),
        ),
        seq(
          oid('2.5.29.37'),
          octet(seq(oid(tamper === 'eku' ? '1.3.6.1.5.5.7.3.2' : '2.23.133.8.3'))),
        ),
      ],
    });
    let sig = await authenticator.sign(
      certInfo,
      aik.keyPair.privateKey,
      COSEAlgorithm.ES256,
    );
    if (tamper === 'signature') sig = flip(sig);

    return {
      fmt: 'tpm',
      attStmt: new Map<CborValue, CborValue>([
        ['ver', tamper === 'ver' ? '1.2' : '2.0'],
        ['alg', tamper === 'rs1' ? -65535 : COSEAlgorithm.ES256],
        ['x5c', [aik.der]],
        ['sig', sig],
        ['certInfo', certInfo],
        ['pubArea', pubArea],
      ]),
    };
  };
}

// ---------------------------------------------------------------------------
// android-key
// ---------------------------------------------------------------------------

export type AndroidKeyTamper =
  | 'signature'
  | 'challenge'
  | 'allApplications'
  | 'origin'
  | 'purpose'
  | 'foreignKey'
  | 'softwareOnly'
  | 'conflictingOrigin'
  | 'extraPurpose'
  | 'duplicateTag'
  | 'missingExtension'
  | 'extraField';

const KM = { PURPOSE: 1, ALL_APPLICATIONS: 600, ORIGIN: 702 };

export function androidKeyAttestation(
  root: TestCertificate,
  tamper?: AndroidKeyTamper,
): Attest {
  return async ({ authData, clientDataHash, authenticator }) => {
    const purposes =
      tamper === 'purpose'
        ? [int(3)]
        : tamper === 'extraPurpose'
          ? [int(2), int(3)]
          : [int(2)];
    const enforced = seq(
      contextTag(KM.PURPOSE, set(...purposes)),
      ...(tamper === 'allApplications'
        ? [contextTag(KM.ALL_APPLICATIONS, nullValue())]
        : []),
      contextTag(KM.ORIGIN, int(tamper === 'origin' ? 1 : 0)),
      ...(tamper === 'duplicateTag' ? [contextTag(KM.ORIGIN, int(0))] : []),
    );
    // IMPORTED in teeEnforced, GENERATED in softwareEnforced.
    const software =
      tamper === 'conflictingOrigin' ? seq(contextTag(KM.ORIGIN, int(0))) : seq();
    const tee =
      tamper === 'conflictingOrigin'
        ? seq(contextTag(KM.PURPOSE, set(int(2))), contextTag(KM.ORIGIN, int(2)))
        : enforced;
    const keyDescription = seq(
      int(3),
      enumerated(1),
      int(4),
      enumerated(1),
      octet(tamper === 'challenge' ? flip(clientDataHash) : clientDataHash),
      octet(new Uint8Array(0)),
      tamper === 'softwareOnly' ? enforced : software,
      tamper === 'softwareOnly' ? seq() : tee,
      ...(tamper === 'extraField' ? [int(0)] : []),
    );
    const foreign =
      tamper === 'foreignKey'
        ? await webcrypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify'],
          )
        : undefined;
    const keyPair = foreign ?? authenticator.keyPair;
    const leaf = await makeCertificate({
      subject: [['2.5.4.3', 'Android Keystore Key']],
      issuer: root,
      serial: 11,
      keyPair,
      extensions:
        tamper === 'missingExtension'
          ? []
          : [seq(oid('1.3.6.1.4.1.11129.2.1.17'), octet(keyDescription))],
    });
    let sig = await authenticator.sign(
      concatBytes(authData, clientDataHash),
      keyPair.privateKey,
      COSEAlgorithm.ES256,
    );
    if (tamper === 'signature') sig = flip(sig);
    return {
      fmt: 'android-key',
      attStmt: new Map<CborValue, CborValue>([
        ['alg', COSEAlgorithm.ES256],
        ['sig', sig],
        ['x5c', [leaf.der]],
      ]),
    };
  };
}

// ---------------------------------------------------------------------------
// apple
// ---------------------------------------------------------------------------

export type AppleTamper = 'nonce' | 'foreignKey' | 'missingExtension' | 'wrongTag';

export function appleAttestation(root: TestCertificate, tamper?: AppleTamper): Attest {
  return async ({ authData, clientDataHash, authenticator }) => {
    const nonce = await sha256(concatBytes(authData, clientDataHash));
    const keyPair =
      tamper === 'foreignKey'
        ? await webcrypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify'],
          )
        : authenticator.keyPair;
    const extensions =
      tamper === 'missingExtension'
        ? []
        : [
            seq(
              oid('1.2.840.113635.100.8.2'),
              octet(
                seq(
                  tlv(
                    tamper === 'wrongTag' ? 0xa2 : 0xa1,
                    octet(tamper === 'nonce' ? flip(nonce) : nonce),
                  ),
                ),
              ),
            ),
          ];
    const credCert = await makeCertificate({
      subject: [['2.5.4.3', 'Apple Credential']],
      issuer: root,
      serial: 12,
      keyPair,
      extensions,
    });
    return {
      fmt: 'apple',
      attStmt: new Map<CborValue, CborValue>([['x5c', [credCert.der, root.der]]]),
    };
  };
}

// ---------------------------------------------------------------------------
// android-safetynet
// ---------------------------------------------------------------------------

export type SafetyNetTamper =
  | 'signature'
  | 'nonce'
  | 'cts'
  | 'stale'
  | 'future'
  | 'hostname'
  | 'algNone'
  | 'hs256'
  | 'shortSignature'
  | 'noX5c'
  | 'noTimestamp';

export function safetyNetAttestation(
  root: TestCertificate,
  tamper?: SafetyNetTamper,
): Attest {
  return async ({ authData, clientDataHash }) => {
    const leaf = await makeCertificate({
      subject: [
        ['2.5.4.3', tamper === 'hostname' ? 'attest.evil.com' : 'attest.android.com'],
      ],
      issuer: root,
      serial: 13,
    });
    const nonce = await sha256(concatBytes(authData, clientDataHash));
    const now = Date.now();
    const header = {
      alg: tamper === 'algNone' ? 'none' : tamper === 'hs256' ? 'HS256' : 'ES256',
      x5c: tamper === 'noX5c' ? [] : [toStdBase64(leaf.der)],
    };
    const payload = {
      nonce: toStdBase64(tamper === 'nonce' ? flip(nonce) : nonce),
      timestampMs:
        tamper === 'noTimestamp'
          ? undefined
          : tamper === 'stale'
            ? now - 120_000
            : tamper === 'future'
              ? now + 60_000
              : now,
      apkPackageName: 'com.google.android.gms',
      ctsProfileMatch: tamper !== 'cts',
      basicIntegrity: true,
    };
    const enc = (o: unknown) => toBase64Url(utf8Encode(JSON.stringify(o)));
    const signingInput = `${enc(header)}.${enc(payload)}`;
    let sig: Uint8Array = new Uint8Array(
      await webcrypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        leaf.keyPair.privateKey,
        copyBytes(utf8Encode(signingInput)),
      ),
    );
    if (tamper === 'signature') sig = flip(sig);
    if (tamper === 'shortSignature') sig = sig.subarray(1);
    return {
      fmt: 'android-safetynet',
      attStmt: new Map<CborValue, CborValue>([
        ['ver', '231213000'],
        ['response', utf8Encode(`${signingInput}.${toBase64Url(sig)}`)],
      ]),
    };
  };
}

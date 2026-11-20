import type { AlgorithmSpec, COSEAlgorithmIdentifier } from '@types';

/** IANA COSE algorithm identifiers relevant to WebAuthn. */
export const COSEAlgorithm = {
  EdDSA: -8,
  Ed25519: -19,
  ES256: -7,
  ES384: -35,
  ES512: -36,
  PS256: -37,
  PS384: -38,
  PS512: -39,
  RS256: -257,
  RS384: -258,
  RS512: -259,
} as const;

export const COSEKeyType = { OKP: 1, EC2: 2, RSA: 3 } as const;
export const COSECurve = { P256: 1, P384: 2, P521: 3, Ed25519: 6 } as const;

/** COSE_Key map labels (RFC 9052 / 9053). */
export const COSEKeyParam = {
  kty: 1,
  alg: 3,
  crv: -1,
  x: -2,
  y: -3,
  n: -1,
  e: -2,
} as const;

const SPECS: ReadonlyMap<COSEAlgorithmIdentifier, AlgorithmSpec> = new Map<
  COSEAlgorithmIdentifier,
  AlgorithmSpec
>([
  [
    COSEAlgorithm.ES256,
    { family: 'ECDSA', hash: 'SHA-256', curve: 'P-256', coseCurve: 1, size: 32 },
  ],
  [
    COSEAlgorithm.ES384,
    { family: 'ECDSA', hash: 'SHA-384', curve: 'P-384', coseCurve: 2, size: 48 },
  ],
  [
    COSEAlgorithm.ES512,
    { family: 'ECDSA', hash: 'SHA-512', curve: 'P-521', coseCurve: 3, size: 66 },
  ],
  [COSEAlgorithm.EdDSA, { family: 'EdDSA', curve: 'Ed25519', coseCurve: 6 }],
  [COSEAlgorithm.Ed25519, { family: 'EdDSA', curve: 'Ed25519', coseCurve: 6 }],
  [COSEAlgorithm.RS256, { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],
  [COSEAlgorithm.RS384, { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }],
  [COSEAlgorithm.RS512, { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }],
  [COSEAlgorithm.PS256, { family: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 }],
  [COSEAlgorithm.PS384, { family: 'RSA-PSS', hash: 'SHA-384', saltLength: 48 }],
  [COSEAlgorithm.PS512, { family: 'RSA-PSS', hash: 'SHA-512', saltLength: 64 }],
]);

/** Supported algorithm spec, or undefined (e.g. RS1 / unknown – always rejected). */
export const getAlgorithmSpec = (
  alg: COSEAlgorithmIdentifier,
): AlgorithmSpec | undefined => SPECS.get(alg);

/** Default `pubKeyCredParams` order: EdDSA, ES256, RS256 (covers ~all authenticators). */
export const DEFAULT_ALGORITHMS: readonly COSEAlgorithmIdentifier[] = [
  COSEAlgorithm.EdDSA,
  COSEAlgorithm.ES256,
  COSEAlgorithm.RS256,
];

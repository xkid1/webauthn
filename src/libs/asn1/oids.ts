import type { AlgorithmSpec } from '@types';

export const OID = {
  ecPublicKey: '1.2.840.10045.2.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
  ed25519: '1.3.101.112',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.3.132.0.34',
  p521: '1.3.132.0.35',
  basicConstraints: '2.5.29.19',
  commonName: '2.5.4.3',
  country: '2.5.4.6',
  organization: '2.5.4.10',
  organizationalUnit: '2.5.4.11',
  /** id-fido-gen-ce-aaguid */
  fidoAaguid: '1.3.6.1.4.1.45724.1.1.4',
  subjectAltName: '2.5.29.17',
  extKeyUsage: '2.5.29.37',
  /** tcg-kp-AIKCertificate (TPM attestation identity key EKU) */
  tcgKpAikCertificate: '2.23.133.8.3',
  tpmManufacturer: '2.23.133.2.1',
  tpmModel: '2.23.133.2.2',
  tpmVersion: '2.23.133.2.3',
  /** Android Keystore KeyDescription attestation extension */
  androidKeyDescription: '1.3.6.1.4.1.11129.2.1.17',
  /** Apple anonymous attestation nonce extension */
  appleNonce: '1.2.840.113635.100.8.2',
} as const;

/** X.509 signatureAlgorithm OID → verification spec. RSA-PSS (params-dependent) is not mapped. */
export const SIGNATURE_ALGORITHMS: ReadonlyMap<string, AlgorithmSpec> = new Map<
  string,
  AlgorithmSpec
>([
  [
    '1.2.840.10045.4.3.2',
    { family: 'ECDSA', hash: 'SHA-256', curve: 'P-256', coseCurve: 1, size: 32 },
  ],
  [
    '1.2.840.10045.4.3.3',
    { family: 'ECDSA', hash: 'SHA-384', curve: 'P-384', coseCurve: 2, size: 48 },
  ],
  [
    '1.2.840.10045.4.3.4',
    { family: 'ECDSA', hash: 'SHA-512', curve: 'P-521', coseCurve: 3, size: 66 },
  ],
  ['1.2.840.113549.1.1.11', { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],
  ['1.2.840.113549.1.1.12', { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }],
  ['1.2.840.113549.1.1.13', { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }],
  ['1.3.101.112', { family: 'EdDSA', curve: 'Ed25519', coseCurve: 6 }],
]);

export const CURVE_BY_OID: ReadonlyMap<string, 'P-256' | 'P-384' | 'P-521'> = new Map([
  [OID.p256, 'P-256'],
  [OID.p384, 'P-384'],
  [OID.p521, 'P-521'],
] as const);

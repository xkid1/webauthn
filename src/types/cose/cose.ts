import type { COSEAlgorithmIdentifier } from '../webauthn';

export type HashName = 'SHA-256' | 'SHA-384' | 'SHA-512';

/** How to verify signatures for one COSE algorithm. */
export type AlgorithmSpec =
  | {
      readonly family: 'ECDSA';
      readonly hash: HashName;
      readonly curve: 'P-256' | 'P-384' | 'P-521';
      readonly coseCurve: number;
      /** Coordinate / scalar size in bytes. */
      readonly size: number;
    }
  | { readonly family: 'EdDSA'; readonly curve: 'Ed25519'; readonly coseCurve: number }
  | { readonly family: 'RSASSA-PKCS1-v1_5'; readonly hash: HashName }
  | { readonly family: 'RSA-PSS'; readonly hash: HashName; readonly saltLength: number };

/** A parsed, validated COSE_Key. */
export type CosePublicKey =
  | {
      readonly kty: 'EC2';
      readonly alg: COSEAlgorithmIdentifier;
      readonly spec: AlgorithmSpec;
      readonly x: Uint8Array;
      readonly y: Uint8Array;
    }
  | {
      readonly kty: 'OKP';
      readonly alg: COSEAlgorithmIdentifier;
      readonly spec: AlgorithmSpec;
      readonly x: Uint8Array;
    }
  | {
      readonly kty: 'RSA';
      readonly alg: COSEAlgorithmIdentifier;
      readonly spec: AlgorithmSpec;
      readonly n: Uint8Array;
      readonly e: Uint8Array;
    };

/** WebCrypto JWK plus import / verify parameters for a COSE key (`coseKeyToJwk`). */
export interface CoseWebCryptoParams {
  jwk: Record<string, unknown>;
  importParams: Record<string, unknown>;
  verifyParams: Record<string, unknown>;
}

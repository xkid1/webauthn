import type { AlgorithmSpec, CosePublicKey } from '../cose';
import type { CryptoKeyLike, CryptoLike } from '../runtime';

/** Input for `verifyWithKey`: verify with an already-imported key. */
export interface VerifyWithKeyOptions {
  crypto: CryptoLike;
  key: CryptoKeyLike;
  spec: AlgorithmSpec;
  signature: Uint8Array;
  data: Uint8Array;
}

/** Input for `verifyCoseSignature`. */
export interface VerifyCoseSignatureOptions {
  crypto: CryptoLike;
  /** COSE_Key bytes or an already-parsed key. */
  publicKey: Uint8Array | CosePublicKey;
  signature: Uint8Array;
  data: Uint8Array;
}

/** One DER INTEGER read from an ECDSA signature: the left-padded value and the next offset. */
export interface DerIntegerRead {
  value: Uint8Array;
  next: number;
}

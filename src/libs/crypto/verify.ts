import { copyBytes, WebAuthnError } from '@utils';

import { coseKeyToJwk, parseCoseKey } from '../cose/index.js';

import { derToRawSignature } from './ecdsa.js';

import type {
  AlgorithmSpec,
  CosePublicKey,
  CryptoKeyLike,
  CryptoLike,
  VerifyCoseSignatureOptions,
  VerifyWithKeyOptions,
} from '@types';

/** WebCrypto verify parameters for an algorithm spec. */
export function verifyParamsFor(spec: AlgorithmSpec): Record<string, unknown> {
  switch (spec.family) {
    case 'ECDSA':
      return { name: 'ECDSA', hash: { name: spec.hash } };
    case 'EdDSA':
      return { name: 'Ed25519' };
    case 'RSA-PSS':
      return { name: 'RSA-PSS', saltLength: spec.saltLength };
    case 'RSASSA-PKCS1-v1_5':
      return { name: 'RSASSA-PKCS1-v1_5' };
  }
}

/** Normalise a signature into the format WebCrypto expects for `spec`. */
export const normaliseSignature = (
  spec: AlgorithmSpec,
  signature: Uint8Array,
): Uint8Array =>
  spec.family === 'ECDSA' ? derToRawSignature(signature, spec.size) : signature;

/** Verify with an already-imported key. Never throws for a bad signature – returns false. */
export async function verifyWithKey(options: VerifyWithKeyOptions): Promise<boolean> {
  const { crypto, key, spec, data } = options;
  let signature: Uint8Array;
  try {
    signature = normaliseSignature(spec, options.signature);
  } catch {
    return false;
  }
  try {
    return await crypto.subtle.verify(
      verifyParamsFor(spec),
      key,
      copyBytes(signature),
      copyBytes(data),
    );
  } catch {
    return false;
  }
}

export async function importCoseKey(
  crypto: CryptoLike,
  key: CosePublicKey,
): Promise<CryptoKeyLike> {
  const { jwk, importParams } = coseKeyToJwk(key);
  try {
    return await crypto.subtle.importKey('jwk', jwk, importParams, false, ['verify']);
  } catch (cause) {
    throw new WebAuthnError(
      'INVALID_PUBLIC_KEY',
      `Unable to import ${String(importParams.name)} public key (is it supported by this runtime?)`,
      { cause },
    );
  }
}

/**
 * Verify `signature` over `data` with a COSE public key.
 * Throws SIGNATURE_INVALID if the signature does not verify.
 */
export async function verifyCoseSignature(
  options: VerifyCoseSignatureOptions,
): Promise<void> {
  const cose =
    options.publicKey instanceof Uint8Array
      ? parseCoseKey(options.publicKey)
      : options.publicKey;
  const key = await importCoseKey(options.crypto, cose);
  const ok = await verifyWithKey({
    crypto: options.crypto,
    key,
    spec: cose.spec,
    signature: options.signature,
    data: options.data,
  });
  if (!ok) throw new WebAuthnError('SIGNATURE_INVALID', 'Signature verification failed');
}

import { toBase64Url, WebAuthnError } from '@utils';

import { decodeCborFirst, isCborMap } from '../cbor';

import { COSEKeyParam, COSEKeyType, getAlgorithmSpec } from './algorithms';

import type { CborValue, CosePublicKey, CoseWebCryptoParams } from '@types';

const MIN_RSA_BITS = 2048;

const invalid = (message: string): never => {
  throw new WebAuthnError('INVALID_PUBLIC_KEY', `COSE key: ${message}`);
};

const bytesParam = (
  map: Map<CborValue, CborValue>,
  label: number,
  name: string,
): Uint8Array => {
  const v = map.get(label);
  return v instanceof Uint8Array ? v : invalid(`missing or invalid "${name}"`);
};

const stripLeadingZeros = (b: Uint8Array): Uint8Array => {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i += 1;
  return b.subarray(i);
};

/**
 * Parse and strictly validate a COSE_Key. The algorithm must be present,
 * supported, and consistent with the key type and curve.
 */
export function parseCoseKey(
  input: Uint8Array | Map<CborValue, CborValue>,
): CosePublicKey {
  let map: Map<CborValue, CborValue>;
  if (input instanceof Uint8Array) {
    const { value, length } = decodeCborFirst(input);
    if (length !== input.length) invalid('trailing bytes');
    if (!isCborMap(value)) return invalid('not a CBOR map');
    map = value;
  } else {
    map = input;
  }

  const kty = map.get(COSEKeyParam.kty);
  const alg = map.get(COSEKeyParam.alg);
  if (typeof alg !== 'number') return invalid('missing "alg"');
  const spec = getAlgorithmSpec(alg);
  if (!spec)
    throw new WebAuthnError(
      'UNSUPPORTED_ALGORITHM',
      `COSE algorithm ${alg} is not supported`,
    );

  if (kty === COSEKeyType.EC2) {
    if (spec.family !== 'ECDSA') return invalid('alg does not match kty EC2');
    if (map.get(COSEKeyParam.crv) !== spec.coseCurve)
      return invalid('curve does not match alg');
    const x = bytesParam(map, COSEKeyParam.x, 'x');
    const y = bytesParam(map, COSEKeyParam.y, 'y');
    if (x.length !== spec.size || y.length !== spec.size)
      return invalid('bad coordinate length');
    return { kty: 'EC2', alg, spec, x, y };
  }
  if (kty === COSEKeyType.OKP) {
    if (spec.family !== 'EdDSA') return invalid('alg does not match kty OKP');
    if (map.get(COSEKeyParam.crv) !== spec.coseCurve)
      return invalid('curve does not match alg');
    const x = bytesParam(map, COSEKeyParam.x, 'x');
    if (x.length !== 32) return invalid('bad Ed25519 key length');
    return { kty: 'OKP', alg, spec, x };
  }
  if (kty === COSEKeyType.RSA) {
    if (spec.family !== 'RSASSA-PKCS1-v1_5' && spec.family !== 'RSA-PSS') {
      return invalid('alg does not match kty RSA');
    }
    const n = stripLeadingZeros(bytesParam(map, COSEKeyParam.n, 'n'));
    const e = stripLeadingZeros(bytesParam(map, COSEKeyParam.e, 'e'));
    if (n.length * 8 < MIN_RSA_BITS)
      return invalid(`RSA modulus below ${MIN_RSA_BITS} bits`);
    if (e.length === 0 || e.length > 8) return invalid('bad RSA exponent');
    return { kty: 'RSA', alg, spec, n, e };
  }
  return invalid('unsupported kty');
}

/** WebCrypto JWK + import/verify parameters for a parsed COSE key. */
export function coseKeyToJwk(key: CosePublicKey): CoseWebCryptoParams {
  const { spec } = key;
  switch (spec.family) {
    case 'ECDSA': {
      if (key.kty !== 'EC2') return invalid('kty mismatch');
      return {
        jwk: {
          kty: 'EC',
          crv: spec.curve,
          x: toBase64Url(key.x),
          y: toBase64Url(key.y),
          ext: true,
        },
        importParams: { name: 'ECDSA', namedCurve: spec.curve },
        verifyParams: { name: 'ECDSA', hash: { name: spec.hash } },
      };
    }
    case 'EdDSA': {
      if (key.kty !== 'OKP') return invalid('kty mismatch');
      return {
        jwk: { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(key.x), ext: true },
        importParams: { name: 'Ed25519' },
        verifyParams: { name: 'Ed25519' },
      };
    }
    case 'RSASSA-PKCS1-v1_5':
    case 'RSA-PSS': {
      if (key.kty !== 'RSA') return invalid('kty mismatch');
      return {
        jwk: { kty: 'RSA', n: toBase64Url(key.n), e: toBase64Url(key.e), ext: true },
        importParams: { name: spec.family, hash: { name: spec.hash } },
        verifyParams:
          spec.family === 'RSA-PSS'
            ? { name: 'RSA-PSS', saltLength: spec.saltLength }
            : { name: 'RSASSA-PKCS1-v1_5' },
      };
    }
  }
}

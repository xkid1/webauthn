import {
  concatBytes,
  fromBase64Url,
  isRecord,
  sha256,
  timingSafeEqual,
  utf8Decode,
  utf8Encode,
  WebAuthnError,
} from '@utils';

import {
  getSubjectAltNameDnsNames,
  importCertificateKey,
  OID,
  parseCertificate,
} from '../../asn1';
import { COSEAlgorithm, getAlgorithmSpec } from '../../cose';
import { rawToDerSignature, verifyWithKey } from '../../crypto';
import { assertOnlyKeys, stmtBytes } from '../statement';
import { verifyCertificateChain } from '../trust';

import type {
  AndroidSafetyNetVerifierOptions,
  AttestationVerifier,
  COSEAlgorithmIdentifier,
} from '@types';

const invalid = (message: string): never => {
  throw new WebAuthnError('ATTESTATION_INVALID', `android-safetynet: ${message}`);
};

const SAFETYNET_HOSTNAME = 'attest.android.com';
const MAX_X5C = 8;

/** JWS "alg" → COSE algorithm. "none", HMAC and RS1-style algorithms are rejected. */
const JWS_ALGORITHMS: ReadonlyMap<string, COSEAlgorithmIdentifier> = new Map([
  ['RS256', COSEAlgorithm.RS256],
  ['RS384', COSEAlgorithm.RS384],
  ['RS512', COSEAlgorithm.RS512],
  ['PS256', COSEAlgorithm.PS256],
  ['PS384', COSEAlgorithm.PS384],
  ['PS512', COSEAlgorithm.PS512],
  ['ES256', COSEAlgorithm.ES256],
  ['ES384', COSEAlgorithm.ES384],
  ['ES512', COSEAlgorithm.ES512],
]);

function decodeJsonSegment(segment: string, what: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(fromBase64Url(segment)));
  } catch {
    return invalid(`JWS ${what} is not valid base64url JSON`);
  }
  return isRecord(parsed) ? parsed : invalid(`JWS ${what} is not an object`);
}

/**
 * Build an "android-safetynet" verifier (WebAuthn §8.5). The default instance
 * is built in; register a customised one via `attestationVerifiers`.
 */
export function createAndroidSafetyNetVerifier(
  options: AndroidSafetyNetVerifierOptions = {},
): AttestationVerifier {
  const maxAgeMs = options.maxAgeMs ?? 60_000;
  const clockSkewMs = options.clockSkewMs ?? 0;
  if (!(maxAgeMs > 0) || !(clockSkewMs >= 0)) {
    throw new WebAuthnError('INVALID_CONFIG', 'android-safetynet: invalid time window');
  }

  return async (ctx) => {
    assertOnlyKeys(ctx.attStmt, ['ver', 'response']);
    const ver = ctx.attStmt.get('ver');
    if (typeof ver !== 'string' || ver.length === 0)
      invalid('"ver" must be a non-empty string');
    const response = utf8Decode(stmtBytes(ctx.attStmt, 'response'));

    // §8.5: response is a compact JWS.
    const parts = response.split('.');
    if (parts.length !== 3) return invalid('response is not a compact JWS');
    const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
    const header = decodeJsonSegment(headerB64, 'header');
    const payload = decodeJsonSegment(payloadB64, 'payload');

    const coseAlg =
      typeof header.alg === 'string' ? JWS_ALGORITHMS.get(header.alg) : undefined;
    const spec = coseAlg === undefined ? undefined : getAlgorithmSpec(coseAlg);
    if (!spec) return invalid('unsupported JWS alg');

    const rawX5c = header.x5c;
    if (!Array.isArray(rawX5c) || rawX5c.length === 0 || rawX5c.length > MAX_X5C) {
      return invalid('JWS header x5c must be a non-empty array');
    }
    const x5c = rawX5c.map((c) => {
      if (typeof c !== 'string') return invalid('JWS x5c entries must be strings');
      try {
        return fromBase64Url(c, { lenient: true });
      } catch {
        return invalid('JWS x5c entry is not base64');
      }
    });

    // §8.5 step 3: nonce = base64(SHA-256(authenticatorData || clientDataHash)).
    const expectedNonce = await sha256(
      concatBytes(ctx.authData, ctx.clientDataHash),
      ctx.crypto,
    );
    if (typeof payload.nonce !== 'string') return invalid('payload nonce is missing');
    let nonce: Uint8Array;
    try {
      nonce = fromBase64Url(payload.nonce, { lenient: true });
    } catch {
      return invalid('payload nonce is not base64');
    }
    if (!timingSafeEqual(nonce, expectedNonce)) invalid('payload nonce does not match');

    // §8.5 step 4: the attestation certificate is issued to attest.android.com.
    const leaf = parseCertificate(x5c[0]!);
    const hostnames = [
      ...getSubjectAltNameDnsNames(leaf),
      leaf.subjectAttributes.get(OID.commonName),
    ];
    if (!hostnames.includes(SAFETYNET_HOSTNAME)) {
      invalid(`attestation certificate is not issued to ${SAFETYNET_HOSTNAME}`);
    }

    // §8.5 step 4: verify the JWS signature with the leaf key.
    let signature: Uint8Array;
    try {
      signature = fromBase64Url(signatureB64);
    } catch {
      return invalid('JWS signature is not base64url');
    }
    if (spec.family === 'ECDSA') {
      // JWS ECDSA signatures are raw r || s (RFC 7518 §3.4).
      if (signature.length !== spec.size * 2)
        invalid('JWS ECDSA signature has the wrong length');
      signature = rawToDerSignature(signature);
    }
    const key = await importCertificateKey(ctx.crypto, leaf, spec);
    const signingInput = utf8Encode(`${headerB64}.${payloadB64}`);
    if (
      !(await verifyWithKey({
        crypto: ctx.crypto,
        key,
        spec,
        signature,
        data: signingInput,
      }))
    ) {
      invalid('JWS signature is invalid');
    }

    // §8.5 step 5: ctsProfileMatch must be true; the response must be fresh.
    if (payload.ctsProfileMatch !== true) invalid('ctsProfileMatch is not true');
    const timestamp = payload.timestampMs;
    if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) {
      return invalid('payload timestampMs is missing');
    }
    if (timestamp > ctx.now + clockSkewMs)
      invalid('payload timestampMs is in the future');
    if (ctx.now - timestamp > maxAgeMs) invalid('payload timestampMs is too old');

    const trusted = await verifyCertificateChain({
      crypto: ctx.crypto,
      chain: x5c,
      trustAnchors: ctx.trustAnchors,
      now: ctx.now,
    });
    return { type: 'basic', trustPath: x5c, trusted };
  };
}

/** WebAuthn §8.5 – "android-safetynet" (deprecated by Google, still in the spec). */
export const verifyAndroidSafetyNetAttestation: AttestationVerifier =
  createAndroidSafetyNetVerifier();

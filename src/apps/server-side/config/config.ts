import {
  BUILT_IN_ATTESTATION_VERIFIERS,
  DEFAULT_ALGORITHMS,
  getAlgorithmSpec,
} from '@libs';
import {
  isHostWithinRpId,
  isValidOrigin,
  isValidRpId,
  originHost,
  resolveCrypto,
  WebAuthnError,
} from '@utils';

import type { RelyingPartyConfig, ResolvedRelyingPartyConfig } from '@types';

export const DEFAULTS = {
  timeout: 300_000,
  userVerification: 'preferred',
  attestation: 'none',
  challengeSize: 32,
  counterPolicy: 'strict',
} as const;

const MIN_TIMEOUT = 10_000;
const MAX_TIMEOUT = 600_000;

const invalid = (message: string): never => {
  throw new WebAuthnError('INVALID_CONFIG', message);
};

/**
 * Validate and freeze a relying-party configuration. Fails fast on anything
 * that would weaken security (http origins, wildcard-ish values, RS1, tiny
 * challenges, cross-origin without a top-origin allowlist…).
 */
export function resolveConfig(config: RelyingPartyConfig): ResolvedRelyingPartyConfig {
  const { rpId, rpName, origins } = config;

  if (typeof rpId !== 'string' || !isValidRpId(rpId)) {
    invalid(
      'rpId must be a lowercase domain such as "example.com" (no scheme, port or path)',
    );
  }
  if (typeof rpName !== 'string' || rpName.trim().length === 0)
    invalid('rpName is required');
  if (!Array.isArray(origins) || origins.length === 0)
    invalid('origins must be a non-empty array');

  for (const origin of origins as readonly unknown[]) {
    if (typeof origin !== 'string' || !isValidOrigin(origin)) {
      invalid(
        `Invalid origin "${String(origin)}". Use https://host[:port], http://localhost[:port] or android:apk-key-hash:…`,
      );
    }
    const host = originHost(origin as string);
    if (host !== undefined && !isHostWithinRpId(host, rpId)) {
      invalid(`Origin "${origin as string}" is not within rpId "${rpId}"`);
    }
  }

  const timeout = config.timeout ?? DEFAULTS.timeout;
  if (!Number.isInteger(timeout) || timeout < MIN_TIMEOUT || timeout > MAX_TIMEOUT) {
    invalid(`timeout must be an integer between ${MIN_TIMEOUT} and ${MAX_TIMEOUT} ms`);
  }

  const challengeSize = config.challengeSize ?? DEFAULTS.challengeSize;
  if (!Number.isInteger(challengeSize) || challengeSize < 16 || challengeSize > 64) {
    invalid('challengeSize must be an integer between 16 and 64 bytes');
  }

  const supportedAlgorithms = [...(config.supportedAlgorithms ?? DEFAULT_ALGORITHMS)];
  if (supportedAlgorithms.length === 0) invalid('supportedAlgorithms must not be empty');
  for (const alg of supportedAlgorithms) {
    if (!getAlgorithmSpec(alg)) invalid(`Unsupported COSE algorithm ${alg}`);
  }

  const allowCrossOrigin = config.allowCrossOrigin ?? false;
  const allowedTopOrigins = [...(config.allowedTopOrigins ?? [])];
  if (allowCrossOrigin && allowedTopOrigins.length === 0) {
    invalid('allowCrossOrigin requires a non-empty allowedTopOrigins list');
  }
  for (const top of allowedTopOrigins) {
    if (!isValidOrigin(top)) invalid(`Invalid top origin "${top}"`);
  }

  const userVerification = config.userVerification ?? DEFAULTS.userVerification;
  const trustAnchors = [...(config.trustAnchors ?? [])];
  const requireTrustedAttestation = config.requireTrustedAttestation ?? false;
  if (requireTrustedAttestation && trustAnchors.length === 0) {
    invalid('requireTrustedAttestation needs at least one trust anchor');
  }

  const attestationVerifiers = {
    ...BUILT_IN_ATTESTATION_VERIFIERS,
    ...config.attestationVerifiers,
  };

  return Object.freeze({
    rpId,
    rpName,
    origins: Object.freeze([...origins]),
    timeout,
    userVerification,
    requireUserVerification:
      config.requireUserVerification ?? userVerification === 'required',
    attestation: config.attestation ?? DEFAULTS.attestation,
    supportedAlgorithms: Object.freeze(supportedAlgorithms),
    authenticatorSelection: Object.freeze({ ...config.authenticatorSelection }),
    hints: Object.freeze([...(config.hints ?? [])]),
    challengeSize,
    allowCrossOrigin,
    allowedTopOrigins: Object.freeze(allowedTopOrigins),
    counterPolicy: config.counterPolicy ?? DEFAULTS.counterPolicy,
    attestationVerifiers: Object.freeze(attestationVerifiers),
    trustAnchors: Object.freeze(trustAnchors),
    requireTrustedAttestation,
    crypto: resolveCrypto(config.crypto),
    now: config.now ?? Date.now,
  });
}

/**
 * Unit-test support for attestation statement verifiers: builds a real
 * AttestationContext (as §7.1 would hand it to a verifier) from a
 * SoftAuthenticator registration, so verifiers can be tested directly inside
 * the libs layer without going through @apps.
 */
import { webcrypto } from 'node:crypto';

import { beforeAll, expect, it } from 'vitest';

import { COSEAlgorithm, parseAttestationObject, parseAuthenticatorData } from '@libs';
import { fromBase64Url, randomBytes, sha256, toBase64Url } from '@utils';

import {
  type Alg,
  type RegisterOverrides,
  RP_ID,
  SoftAuthenticator,
} from './authenticator.js';
import { makeCertificate, ROOT_SUBJECT, type TestCertificate } from './der.js';

import type {
  AttestationContext,
  AttestationResult,
  AttestationType,
  AttestationVerifier,
  CryptoLike,
  PublicKeyCredentialCreationOptionsJSON,
} from '@types';

export type Attest = NonNullable<RegisterOverrides['attest']>;

/** Node's WebCrypto typed as the library's structural CryptoLike. */
export const testCrypto = webcrypto as unknown as CryptoLike;

/** A self-signed test root CA. */
export const makeTestRoot = (serial = 1): Promise<TestCertificate> =>
  makeCertificate({ subject: ROOT_SUBJECT, ca: true, serial });

/**
 * Register a fresh credential and return the context a verifier receives.
 * `statement` is either a custom builder (`attest`) or the SoftAuthenticator's
 * built-in `format` options (none / packed / fido-u2f).
 */
export async function attestationContext(
  statement: Attest | RegisterOverrides,
  options: { alg?: Alg; trustAnchors?: readonly Uint8Array[]; now?: number } = {},
): Promise<AttestationContext> {
  const overrides: RegisterOverrides =
    typeof statement === 'function' ? { attest: statement } : statement;
  const authenticator = await SoftAuthenticator.create(
    options.alg ?? COSEAlgorithm.ES256,
  );
  const creation = {
    rp: { id: RP_ID, name: 'Test' },
    user: { id: toBase64Url(randomBytes(16)), name: 'alice', displayName: 'Alice' },
    challenge: toBase64Url(randomBytes(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: authenticator.alg }],
  } satisfies PublicKeyCredentialCreationOptionsJSON;
  const response = await authenticator.register(creation, overrides);
  const { fmt, attStmt, authData } = parseAttestationObject(
    fromBase64Url(response.response.attestationObject),
  );
  return {
    format: fmt,
    attStmt,
    authData,
    parsedAuthData: parseAuthenticatorData(authData),
    clientDataHash: await sha256(
      fromBase64Url(response.response.clientDataJSON),
      testCrypto,
    ),
    crypto: testCrypto,
    trustAnchors: options.trustAnchors ?? [],
    now: options.now ?? Date.now(),
  };
}

/**
 * Shared trust checks for one format: trusted only when the chain ends at a
 * configured anchor, untrusted without anchors or with a foreign anchor.
 */
export function attestationTrustSuite(options: {
  verify: AttestationVerifier;
  type: AttestationType;
  build: (root: TestCertificate) => Attest;
}): void {
  let root: TestCertificate;
  let stranger: TestCertificate;
  beforeAll(async () => {
    root = await makeTestRoot();
    stranger = await makeTestRoot(99);
  });

  it('verifies and chains to the configured anchor', async () => {
    const ctx = await attestationContext(options.build(root), {
      trustAnchors: [root.der],
    });
    const result = await options.verify(ctx);
    expect(result).toMatchObject({ type: options.type, trusted: true });
    expect(result.trustPath.length).toBeGreaterThan(0);
  });

  it('is untrusted without anchors', async () => {
    const result = await options.verify(await attestationContext(options.build(root)));
    expect(result).toMatchObject({ type: options.type, trusted: false });
  });

  it('is untrusted with a foreign anchor', async () => {
    const ctx = await attestationContext(options.build(root), {
      trustAnchors: [stranger.der],
    });
    await expect(options.verify(ctx)).resolves.toMatchObject({ trusted: false });
  });
}

/** Run `verify` on a fresh statement built by `attest`. */
export async function verifyStatement(
  verify: AttestationVerifier,
  attest: Attest,
): Promise<AttestationResult> {
  return verify(await attestationContext(attest));
}

/** Matcher for a rejected statement: `code` plus a message matching `message`. */
export const rejection = (message: RegExp, code = 'ATTESTATION_INVALID') => ({
  code,
  message: expect.stringMatching(message) as string,
});

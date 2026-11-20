import { webcrypto } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { COSEAlgorithm, decodeCbor, encodeCbor } from '@libs';
import { fromBase64Url, toBase64Url } from '@utils';
import {
  type Alg,
  ATTESTATION_SUBJECT,
  TEST_RP as base,
  FLAGS,
  makeCertificate,
  makeTestRoot,
  registerCredential,
  ROOT_SUBJECT,
  RP_ID,
  SoftAuthenticator,
  TEST_USER as user,
} from '../../../../tests/index.js';

import { resolveConfig } from '../config/index.js';

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from './registration.js';

import type { AttestationVerifier, CborValue } from '@types';

describe('generateRegistrationOptions', () => {
  const config = resolveConfig(base);

  it('produces spec-shaped options', () => {
    const o = generateRegistrationOptions(config, {
      user,
      excludeCredentials: [{ id: 'AAAA', transports: ['usb', 'bogus' as never] }],
    });
    expect(o.rp).toEqual({ id: RP_ID, name: 'Example' });
    expect(fromBase64Url(o.challenge)).toHaveLength(32);
    expect(fromBase64Url(o.user.id)).toHaveLength(32);
    expect(o.pubKeyCredParams.map((p) => p.alg)).toEqual([-8, -7, -257]);
    expect(o.authenticatorSelection).toMatchObject({
      residentKey: 'preferred',
      requireResidentKey: false,
    });
    expect(o.excludeCredentials).toEqual([
      { type: 'public-key', id: 'AAAA', transports: ['usb'] },
    ]);
    expect(o.extensions).toEqual({ credProps: true });
  });

  it('never reuses challenges and validates user input', () => {
    const a = generateRegistrationOptions(config, { user });
    const b = generateRegistrationOptions(config, { user });
    expect(a.challenge).not.toBe(b.challenge);
    expect(() => generateRegistrationOptions(config, { user: { name: '' } })).toThrow();
    expect(() =>
      generateRegistrationOptions(config, { user: { ...user, id: new Uint8Array(65) } }),
    ).toThrow();
    expect(() =>
      generateRegistrationOptions(config, { user, challenge: new Uint8Array(8) }),
    ).toThrow();
  });
});

describe('verifyRegistrationResponse', () => {
  const config = resolveConfig(base);

  it.each<Alg>([COSEAlgorithm.ES256, COSEAlgorithm.EdDSA, COSEAlgorithm.RS256])(
    'accepts "none" attestation with alg %i',
    async (alg) => {
      const { auth, result } = await registerCredential(config, alg);
      expect(result.credential).toMatchObject({
        id: auth.id,
        algorithm: alg,
        counter: 0,
        transports: ['internal', 'hybrid'],
        aaguid: '00000000-0000-0000-0000-000000000000',
        deviceType: 'singleDevice',
        attachment: 'platform',
      });
      expect(fromBase64Url(result.credential.publicKey)).toEqual(auth.cosePublicKey);
      expect(result.attestation).toMatchObject({
        format: 'none',
        type: 'none',
        trusted: false,
      });
      expect(result.userVerified).toBe(true);
    },
  );

  it('reports multi-device passkeys and credProps', async () => {
    const auth = await SoftAuthenticator.create();
    const options = generateRegistrationOptions(config, { user });
    const response = await auth.register(options, {
      flags: FLAGS.UP | FLAGS.UV | FLAGS.AT | FLAGS.BE | FLAGS.BS,
      credProps: true,
    });
    const { credential } = await verifyRegistrationResponse(config, {
      response,
      expectedChallenge: options.challenge,
    });
    expect(credential).toMatchObject({
      deviceType: 'multiDevice',
      backupEligible: true,
      backedUp: true,
      discoverable: true,
    });
  });

  it('reports attestation trust and enforces requireTrustedAttestation', async () => {
    const aaguid = webcrypto.getRandomValues(new Uint8Array(16));
    const root = await makeTestRoot();
    const leaf = await makeCertificate({
      subject: ATTESTATION_SUBJECT,
      issuer: root,
      aaguid,
      serial: 2,
    });
    const trustedConfig = resolveConfig({
      ...base,
      attestation: 'direct',
      trustAnchors: [root.der],
      requireTrustedAttestation: true,
    });
    const auth = await SoftAuthenticator.create();
    const options = generateRegistrationOptions(trustedConfig, { user });
    const response = await auth.register(options, {
      format: 'packed-x5c',
      attestationChain: [leaf],
      aaguid,
    });
    const input = { response, expectedChallenge: options.challenge };

    const trusted = await verifyRegistrationResponse(trustedConfig, input);
    expect(trusted.attestation).toMatchObject({
      format: 'packed',
      type: 'basic',
      trusted: true,
    });
    expect(trusted.attestation.trustPath).toHaveLength(1);

    expect((await verifyRegistrationResponse(config, input)).attestation.trusted).toBe(
      false,
    );

    const stranger = await makeCertificate({ subject: ROOT_SUBJECT, ca: true });
    const strict = resolveConfig({
      ...base,
      trustAnchors: [stranger.der],
      requireTrustedAttestation: true,
    });
    await expect(verifyRegistrationResponse(strict, input)).rejects.toMatchObject({
      code: 'ATTESTATION_UNTRUSTED',
    });
  });

  it('supports custom attestation verifiers', async () => {
    const custom: AttestationVerifier = () =>
      Promise.resolve({ type: 'basic', trustPath: [], trusted: true });
    const withCustom = resolveConfig({ ...base, attestationVerifiers: { none: custom } });
    const { result } = await registerCredential(withCustom);
    expect(result.attestation).toMatchObject({ type: 'basic', trusted: true });
  });

  it.each<[string, Parameters<SoftAuthenticator['register']>[1], string]>([
    ['challenge', { challenge: toBase64Url(new Uint8Array(32)) }, 'CHALLENGE_MISMATCH'],
    ['origin', { origin: 'https://evil.example.org' }, 'ORIGIN_MISMATCH'],
    ['type', { type: 'webauthn.get' }, 'TYPE_MISMATCH'],
    ['rpId', { rpId: 'evil.com' }, 'RP_ID_MISMATCH'],
    ['UP flag', { flags: FLAGS.UV | FLAGS.AT }, 'USER_PRESENCE_REQUIRED'],
    ['AT flag', { flags: FLAGS.UP }, 'INVALID_AUTHENTICATOR_DATA'],
    [
      'cross origin',
      { crossOrigin: true, topOrigin: 'https://evil.com' },
      'CROSS_ORIGIN_NOT_ALLOWED',
    ],
  ])('rejects tampered %s', async (_label, overrides, code) => {
    const auth = await SoftAuthenticator.create();
    const options = generateRegistrationOptions(config, { user });
    const response = await auth.register(options, overrides);
    await expect(
      verifyRegistrationResponse(config, {
        response,
        expectedChallenge: options.challenge,
      }),
    ).rejects.toMatchObject({ code });
  });

  it('enforces UV when required', async () => {
    const strict = resolveConfig({ ...base, userVerification: 'required' });
    const auth = await SoftAuthenticator.create();
    const options = generateRegistrationOptions(strict, { user });
    const response = await auth.register(options, { flags: FLAGS.UP | FLAGS.AT });
    await expect(
      verifyRegistrationResponse(strict, {
        response,
        expectedChallenge: options.challenge,
      }),
    ).rejects.toMatchObject({ code: 'USER_VERIFICATION_REQUIRED' });
  });

  it('rejects algorithms that were not requested', async () => {
    const es256Only = resolveConfig({
      ...base,
      supportedAlgorithms: [COSEAlgorithm.ES256],
    });
    const auth = await SoftAuthenticator.create(COSEAlgorithm.EdDSA);
    const options = generateRegistrationOptions(es256Only, { user });
    const response = await auth.register(options);
    await expect(
      verifyRegistrationResponse(es256Only, {
        response,
        expectedChallenge: options.challenge,
      }),
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_ALGORITHM' });
  });

  it('rejects id/rawId and credential-id mismatches and malformed JSON', async () => {
    const auth = await SoftAuthenticator.create();
    const options = generateRegistrationOptions(config, { user });
    const response = await auth.register(options);
    const other = toBase64Url(new Uint8Array(32).fill(9));
    const verify = (r: typeof response) =>
      verifyRegistrationResponse(config, {
        response: r,
        expectedChallenge: options.challenge,
      });

    await expect(verify({ ...response, id: other })).rejects.toMatchObject({
      code: 'CREDENTIAL_ID_MISMATCH',
    });
    await expect(verify({ ...response, id: other, rawId: other })).rejects.toMatchObject({
      code: 'CREDENTIAL_ID_MISMATCH',
    });
    await expect(verify({ ...response, type: 'x' as never })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(verify(null as never)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('rejects unknown attestation formats', async () => {
    const auth = await SoftAuthenticator.create();
    const options = generateRegistrationOptions(config, { user });
    const response = await auth.register(options);
    const obj = decodeCbor(fromBase64Url(response.response.attestationObject)) as Map<
      CborValue,
      CborValue
    >;
    obj.set('fmt', 'vendor-proprietary');
    const tampered = {
      ...response,
      response: { ...response.response, attestationObject: toBase64Url(encodeCbor(obj)) },
    };
    await expect(
      verifyRegistrationResponse(resolveConfig({ ...base, attestationVerifiers: {} }), {
        response: tampered,
        expectedChallenge: options.challenge,
      }),
    ).rejects.toMatchObject({ code: 'ATTESTATION_FORMAT_UNSUPPORTED' });
  });
});

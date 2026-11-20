import { describe, expect, it } from 'vitest';

import { COSEAlgorithm } from '@libs';
import { toBase64Url } from '@utils';
import {
  TEST_RP as base,
  FLAGS,
  registerCredential,
  type SoftAuthenticator,
} from '../../../../tests/index.js';

import { resolveConfig } from '../config/index.js';

import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from './authentication.js';

describe('verifyAuthenticationResponse', () => {
  const config = resolveConfig(base);

  it('verifies assertions for every algorithm and advances the counter', async () => {
    for (const alg of [
      COSEAlgorithm.ES256,
      COSEAlgorithm.EdDSA,
      COSEAlgorithm.RS256,
    ] as const) {
      const { auth, result } = await registerCredential(config, alg);
      const options = generateAuthenticationOptions(config, {
        allowCredentials: [result.credential],
      });
      expect(options.allowCredentials?.[0]?.id).toBe(auth.id);
      const response = await auth.authenticate(options);
      const verified = await verifyAuthenticationResponse(config, {
        response,
        expectedChallenge: options.challenge,
        credential: result.credential,
        expectedUserHandle: auth.userHandle!,
      });
      expect(verified).toMatchObject({
        credentialId: auth.id,
        newCounter: 1,
        userVerified: true,
        userHandle: auth.userHandle,
      });
    }
  });

  it('allows 0/0 counters (synced passkeys)', async () => {
    const { auth, result } = await registerCredential(config);
    const options = generateAuthenticationOptions(config);
    const response = await auth.authenticate(options, { signCount: 0 });
    await expect(
      verifyAuthenticationResponse(config, {
        response,
        expectedChallenge: options.challenge,
        credential: result.credential,
      }),
    ).resolves.toMatchObject({ newCounter: 0 });
  });

  it('detects counter regression (strict throws, lenient warns)', async () => {
    const { auth, result } = await registerCredential(config);
    const stored = { ...result.credential, counter: 10 };
    const options = generateAuthenticationOptions(config);
    const response = await auth.authenticate(options, { signCount: 5 });
    const input = { response, expectedChallenge: options.challenge, credential: stored };
    await expect(verifyAuthenticationResponse(config, input)).rejects.toMatchObject({
      code: 'COUNTER_REGRESSION',
    });
    const lenient = resolveConfig({ ...base, counterPolicy: 'lenient' });
    await expect(verifyAuthenticationResponse(lenient, input)).resolves.toMatchObject({
      counterWarning: true,
      newCounter: 10,
    });
  });

  it.each<[string, Parameters<SoftAuthenticator['authenticate']>[1], string]>([
    ['signature', { corruptSignature: true }, 'SIGNATURE_INVALID'],
    ['challenge', { challenge: toBase64Url(new Uint8Array(32)) }, 'CHALLENGE_MISMATCH'],
    ['type', { type: 'webauthn.create' }, 'TYPE_MISMATCH'],
    ['origin', { origin: 'https://example.com.evil.io' }, 'ORIGIN_MISMATCH'],
    ['rpId', { rpId: 'evil.com' }, 'RP_ID_MISMATCH'],
    ['UP flag', { flags: FLAGS.UV }, 'USER_PRESENCE_REQUIRED'],
    [
      'user handle',
      { userHandle: toBase64Url(new Uint8Array(16)) },
      'USER_HANDLE_MISMATCH',
    ],
  ])('rejects tampered %s', async (_label, overrides, code) => {
    const { auth, result } = await registerCredential(config);
    const options = generateAuthenticationOptions(config);
    const response = await auth.authenticate(options, overrides);
    await expect(
      verifyAuthenticationResponse(config, {
        response,
        expectedChallenge: options.challenge,
        credential: result.credential,
        expectedUserHandle: auth.userHandle!,
      }),
    ).rejects.toMatchObject({ code });
  });

  it('rejects an assertion from a different credential', async () => {
    const { result } = await registerCredential(config);
    const other = await registerCredential(config);
    const options = generateAuthenticationOptions(config);
    const response = await other.auth.authenticate(options);
    await expect(
      verifyAuthenticationResponse(config, {
        response,
        expectedChallenge: options.challenge,
        credential: result.credential,
      }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_ID_MISMATCH' });
  });

  it('enforces UV per ceremony', async () => {
    const { auth, result } = await registerCredential(config);
    const options = generateAuthenticationOptions(config);
    const response = await auth.authenticate(options, { flags: FLAGS.UP });
    await expect(
      verifyAuthenticationResponse(config, {
        response,
        expectedChallenge: options.challenge,
        credential: result.credential,
        requireUserVerification: true,
      }),
    ).rejects.toMatchObject({ code: 'USER_VERIFICATION_REQUIRED' });
  });
});

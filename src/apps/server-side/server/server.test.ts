import { describe, expect, it } from 'vitest';

import {
  TEST_RP as base,
  SoftAuthenticator,
  TEST_USER as user,
} from '../../../../tests/index.js';

import { MemoryChallengeStore } from '../challenge-store/index.js';

import { createWebAuthnServer } from './server.js';

describe('createWebAuthnServer', () => {
  it('runs both ceremonies with single-use session challenges', async () => {
    const server = createWebAuthnServer({
      ...base,
      challengeStore: new MemoryChallengeStore(),
    });
    const auth = await SoftAuthenticator.create();

    const regOptions = await server.generateRegistrationOptions({
      user,
      sessionKey: 'sess-1',
    });
    const regResponse = await auth.register(regOptions);
    const { credential } = await server.verifyRegistration({
      response: regResponse,
      sessionKey: 'sess-1',
    });

    // Replay is impossible: the challenge was consumed.
    await expect(
      server.verifyRegistration({ response: regResponse, sessionKey: 'sess-1' }),
    ).rejects.toMatchObject({ code: 'CHALLENGE_NOT_FOUND' });

    const authOptions = await server.generateAuthenticationOptions({
      sessionKey: 'sess-1',
    });
    const authResponse = await auth.authenticate(authOptions);
    await expect(
      server.verifyAuthentication({
        response: authResponse,
        sessionKey: 'sess-1',
        credential,
      }),
    ).resolves.toMatchObject({ newCounter: 1 });

    // A registration challenge cannot be used for authentication.
    const reg2 = await server.generateRegistrationOptions({ user, sessionKey: 'sess-2' });
    const crossed = await auth.authenticate({ challenge: reg2.challenge });
    await expect(
      server.verifyAuthentication({
        response: crossed,
        sessionKey: 'sess-2',
        credential,
      }),
    ).rejects.toMatchObject({ code: 'CHALLENGE_NOT_FOUND' });
  });

  it('requires a store for sessionKey and supports explicit challenges', async () => {
    const server = createWebAuthnServer(base);
    await expect(
      server.generateRegistrationOptions({ user, sessionKey: 'x' }),
    ).rejects.toMatchObject({ code: 'INVALID_CONFIG' });
    const auth = await SoftAuthenticator.create();
    const options = await server.generateRegistrationOptions({ user });
    await expect(
      server.verifyRegistration({
        response: await auth.register(options),
        expectedChallenge: options.challenge,
      }),
    ).resolves.toBeDefined();
  });
});

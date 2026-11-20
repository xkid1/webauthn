import { afterEach, describe, expect, it, vi } from 'vitest';

import { createWebAuthnServer } from '@apps';
import { installBrowser, SoftAuthenticator, TEST_RP } from '../../../../tests/index.js';

import { cancelCeremony } from '../ceremony/index.js';

import { startRegistration } from './registration.js';

afterEach(() => {
  vi.unstubAllGlobals();
  cancelCeremony();
});

describe('startRegistration', () => {
  it('produces a response the server verifies', async () => {
    const server = createWebAuthnServer(TEST_RP);
    const { create } = installBrowser(await SoftAuthenticator.create());
    const optionsJSON = await server.generateRegistrationOptions({
      user: { name: 'bob' },
    });
    const registration = await startRegistration({ optionsJSON });

    expect(create).toHaveBeenCalledOnce();
    expect(registration.response.transports).toEqual(['internal']);
    expect(registration.response.publicKey).toBeUndefined(); // throwing getter is tolerated
    expect(registration.clientExtensionResults).toEqual({
      credProps: { rk: true },
      prf: { results: { first: 'AQI' } },
    });

    const { credential } = await server.verifyRegistration({
      response: registration,
      expectedChallenge: optionsJSON.challenge,
    });
    expect(credential.discoverable).toBe(true);
  });
});

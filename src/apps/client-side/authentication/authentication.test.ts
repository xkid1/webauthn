import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createWebAuthnServer } from '@apps';
import {
  type AnyRecord,
  installBrowser,
  SoftAuthenticator,
  TEST_RP,
} from '../../../../tests/index.js';

import { cancelCeremony } from '../ceremony/index.js';

import { startAuthentication } from './authentication.js';

afterEach(() => {
  vi.unstubAllGlobals();
  cancelCeremony();
});

describe('startAuthentication', () => {
  const server = createWebAuthnServer(TEST_RP);
  let auth: SoftAuthenticator;
  beforeEach(async () => {
    auth = await SoftAuthenticator.create();
  });

  it('produces an assertion the server verifies', async () => {
    const regOptions = await server.generateRegistrationOptions({
      user: { name: 'bob' },
    });
    const { credential } = await server.verifyRegistration({
      response: await auth.register(regOptions),
      expectedChallenge: regOptions.challenge,
    });

    const { get } = installBrowser(auth);
    const optionsJSON = await server.generateAuthenticationOptions({
      allowCredentials: [credential],
    });
    const assertion = await startAuthentication({ optionsJSON });
    expect(get).toHaveBeenCalledOnce();
    expect(assertion.authenticatorAttachment).toBe('cross-platform');
    await expect(
      server.verifyAuthentication({
        response: assertion,
        expectedChallenge: optionsJSON.challenge,
        credential,
      }),
    ).resolves.toMatchObject({ newCounter: 1 });
  });

  it('treats a null credential as not allowed', async () => {
    installBrowser(auth, { get: () => Promise.resolve(null) });
    const optionsJSON = await server.generateAuthenticationOptions();
    await expect(startAuthentication({ optionsJSON })).rejects.toMatchObject({
      code: 'CEREMONY_NOT_ALLOWED',
    });
  });

  it('passkey autofill: conditional mediation, no allowCredentials, input required', async () => {
    const { get } = installBrowser(auth);
    const optionsJSON = await server.generateAuthenticationOptions({
      allowCredentials: [{ id: auth.id }],
    });

    vi.stubGlobal('document', { querySelectorAll: () => ({ length: 0 }) });
    await expect(
      startAuthentication({ optionsJSON, useBrowserAutofill: true }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    vi.stubGlobal('document', { querySelectorAll: () => ({ length: 1 }) });
    await startAuthentication({ optionsJSON, useBrowserAutofill: true });
    const call = get.mock.calls[0]![0] as unknown as {
      mediation: string;
      publicKey: AnyRecord;
    };
    expect(call.mediation).toBe('conditional');
    expect(call.publicKey.allowCredentials).toBeUndefined();
  });
});

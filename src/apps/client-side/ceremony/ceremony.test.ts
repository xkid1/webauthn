import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createWebAuthnServer } from '@apps';
import {
  domError,
  installBrowser,
  SoftAuthenticator,
  TEST_RP,
} from '../../../../tests/index.js';

import { startAuthentication } from '../authentication/index.js';
import { startRegistration } from '../registration/index.js';

import { cancelCeremony } from './ceremony.js';

afterEach(() => {
  vi.unstubAllGlobals();
  cancelCeremony();
});

describe('ceremony errors and abort handling', () => {
  const server = createWebAuthnServer(TEST_RP);
  let auth: SoftAuthenticator;
  beforeEach(async () => {
    auth = await SoftAuthenticator.create();
  });

  it.each([
    ['NotAllowedError', 'CEREMONY_NOT_ALLOWED'],
    ['InvalidStateError', 'CREDENTIAL_EXCLUDED'],
    ['SecurityError', 'SECURITY_ERROR'],
    ['NotSupportedError', 'NOT_SUPPORTED'],
    ['ConstraintError', 'CONSTRAINT_ERROR'],
    ['WeirdError', 'UNKNOWN_ERROR'],
  ])('maps %s to %s', async (name, code) => {
    installBrowser(auth, { create: () => Promise.reject(domError(name)) });
    const optionsJSON = await server.generateRegistrationOptions({
      user: { name: 'bob' },
    });
    await expect(startRegistration({ optionsJSON })).rejects.toMatchObject({ code });
  });

  it('aborts a pending ceremony when a new one starts, or when the caller aborts', async () => {
    const pending = (opts: { signal?: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        opts.signal?.addEventListener('abort', () => {
          reject(domError('AbortError'));
        });
      });
    installBrowser(auth, { get: pending });
    const optionsJSON = await server.generateAuthenticationOptions();

    const first = startAuthentication({ optionsJSON });
    const second = startAuthentication({ optionsJSON });
    await expect(first).rejects.toMatchObject({ code: 'CEREMONY_ABORTED' });

    cancelCeremony();
    await expect(second).rejects.toMatchObject({ code: 'CEREMONY_ABORTED' });

    const controller = new AbortController();
    const third = startAuthentication({ optionsJSON, signal: controller.signal });
    controller.abort();
    await expect(third).rejects.toMatchObject({ code: 'CEREMONY_ABORTED' });
  });
});

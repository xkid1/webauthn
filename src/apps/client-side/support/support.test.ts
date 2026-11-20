import { afterEach, describe, expect, it, vi } from 'vitest';

import { installBrowser, RP_ID, SoftAuthenticator } from '../../../../tests/index.js';

import { startRegistration } from '../registration/index.js';

import {
  getClientCapabilities,
  isConditionalMediationAvailable,
  isPlatformAuthenticatorAvailable,
  isWebAuthnSupported,
  signals,
} from './support.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('feature detection', () => {
  it('is SSR-safe when no browser globals exist', async () => {
    vi.stubGlobal('navigator', undefined);
    vi.stubGlobal('PublicKeyCredential', undefined);
    expect(isWebAuthnSupported()).toBe(false);
    await expect(isPlatformAuthenticatorAvailable()).resolves.toBe(false);
    await expect(isConditionalMediationAvailable()).resolves.toBe(false);
    await expect(getClientCapabilities()).resolves.toMatchObject({ webauthn: false });
    await expect(startRegistration({ optionsJSON: {} as never })).rejects.toMatchObject({
      code: 'NOT_SUPPORTED',
    });
  });

  it('reports capabilities with fallbacks and the Signal API', async () => {
    installBrowser(await SoftAuthenticator.create());
    expect(isWebAuthnSupported()).toBe(true);
    await expect(getClientCapabilities()).resolves.toMatchObject({
      webauthn: true,
      platformAuthenticator: true,
      conditionalGet: true,
      conditionalCreate: false,
    });
    await expect(signals.unknownCredential(RP_ID, 'AAAA')).resolves.toBe(true);
    await expect(signals.currentUserDetails(RP_ID, 'AAAA', 'a', 'A')).resolves.toBe(
      false,
    );
  });
});

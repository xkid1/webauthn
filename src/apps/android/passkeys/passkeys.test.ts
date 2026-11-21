import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { createWebAuthnServer } from '@apps';
import { fromBase64Url } from '@utils';

import { RP_ID, SoftAuthenticator } from '../../../../tests';
import { androidOriginFromFingerprint } from '../origin';

import {
  createAndroidPasskeyClient,
  normaliseRegistration,
  toAndroidError,
} from './passkeys';

import type { AndroidCredentialBridge } from '@types';

const FINGERPRINT = createHash('sha256')
  .update('release-key')
  .digest('hex')
  .toUpperCase()
  .replace(/(..)(?!$)/gu, '$1:');
const ANDROID_ORIGIN = androidOriginFromFingerprint(FINGERPRINT);

/** Re-encode base64url as padded standard base64, as some native bridges do. */
const toStdB64 = (value: string) => Buffer.from(fromBase64Url(value)).toString('base64');

describe('createAndroidPasskeyClient', () => {
  it('round-trips with the server using a Credential Manager-like bridge', async () => {
    const auth = await SoftAuthenticator.create();
    const server = createWebAuthnServer({
      rpId: RP_ID,
      rpName: 'Example',
      origins: [ANDROID_ORIGIN],
    });

    const bridge: AndroidCredentialBridge = {
      async createCredential(requestJson) {
        const json = await auth.register(JSON.parse(requestJson) as never, {
          origin: ANDROID_ORIGIN,
        });
        // Simulate a bridge that returns padded std base64 and omits rawId.
        const { rawId: _rawId, ...rest } = json;
        return JSON.stringify({
          ...rest,
          id: toStdB64(json.id),
          response: {
            ...json.response,
            clientDataJSON: toStdB64(json.response.clientDataJSON),
          },
        });
      },
      async getCredential(requestJson) {
        return auth.authenticate(JSON.parse(requestJson) as never, {
          origin: ANDROID_ORIGIN,
        });
      },
      isAvailable: () => Promise.resolve(true),
    };

    const client = createAndroidPasskeyClient(bridge);
    await expect(client.isAvailable()).resolves.toBe(true);

    const regOptions = await server.generateRegistrationOptions({
      user: { name: 'dana' },
    });
    const registration = await client.startRegistration({ optionsJSON: regOptions });
    expect(registration.rawId).toBe(auth.id);
    const { credential, origin } = await server.verifyRegistration({
      response: registration,
      expectedChallenge: regOptions.challenge,
    });
    expect(origin).toBe(ANDROID_ORIGIN);

    const authOptions = await server.generateAuthenticationOptions();
    const assertion = await client.startAuthentication({ optionsJSON: authOptions });
    await expect(
      server.verifyAuthentication({
        response: assertion,
        expectedChallenge: authOptions.challenge,
        credential,
      }),
    ).resolves.toMatchObject({ newCounter: 1 });
  });

  it.each([
    [
      { type: 'androidx.credentials.exceptions.CreateCredentialCancellationException' },
      'CEREMONY_NOT_ALLOWED',
    ],
    [{ name: 'NoCredentialException' }, 'CEREMONY_NOT_ALLOWED'],
    [
      { code: 'CreatePublicKeyCredentialDomException', message: 'InvalidStateError' },
      'CREDENTIAL_EXCLUDED',
    ],
    [{ message: 'CreateCredentialUnsupportedException' }, 'NOT_SUPPORTED'],
    [{ message: 'RP ID cannot be validated (assetlinks)' }, 'SECURITY_ERROR'],
    ['boom', 'UNKNOWN_ERROR'],
  ])('maps %o to %s', async (error, code) => {
    expect(toAndroidError(error).code).toBe(code);
    const fail = () => {
      // Native bridges reject with plain objects, not Errors.
      // eslint-disable-next-line @typescript-eslint/only-throw-error
      throw error;
    };
    const client = createAndroidPasskeyClient({
      createCredential: () => Promise.resolve().then(fail),
      getCredential: () => Promise.resolve().then(fail),
    });
    await expect(
      client.startAuthentication({ optionsJSON: { challenge: 'AAAA' } }),
    ).rejects.toMatchObject({ code });
  });

  it('validates bridge output and configuration', () => {
    expect(() => normaliseRegistration('not json')).toThrow();
    expect(() => normaliseRegistration({ id: 'AAAA' })).toThrow();
    expect(() =>
      normaliseRegistration({ id: 'AAAA', rawId: 'AAAB', response: {} }),
    ).toThrow();
    expect(() => createAndroidPasskeyClient({} as AndroidCredentialBridge)).toThrow();
  });
});

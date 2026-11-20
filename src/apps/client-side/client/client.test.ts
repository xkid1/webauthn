import { afterEach, describe, expect, it, vi } from 'vitest';

import { createWebAuthnServer, MemoryChallengeStore } from '@apps';
import {
  type AnyRecord,
  installBrowser,
  ORIGIN,
  RP_ID,
  SoftAuthenticator,
} from '../../../../tests/index.js';

import { cancelCeremony } from '../ceremony/index.js';

import { createWebAuthnClient } from './client.js';

import type { AuthenticationResponseJSON, FetchLike, StoredCredential } from '@types';

afterEach(() => {
  vi.unstubAllGlobals();
  cancelCeremony();
});

describe('createWebAuthnClient', () => {
  it('drives the whole flow through configurable endpoints and headers', async () => {
    const auth = await SoftAuthenticator.create();
    installBrowser(auth);
    const server = createWebAuthnServer({
      rpId: RP_ID,
      rpName: 'Example',
      origins: [ORIGIN],
      challengeStore: new MemoryChallengeStore(),
    });
    const credentials = new Map<string, StoredCredential>();
    const seen: { url: string; headers: Record<string, string> }[] = [];

    const fetchMock: FetchLike = async (url, init) => {
      seen.push({ url, headers: init.headers });
      const body = JSON.parse(init.body ?? '{}') as AnyRecord;
      const json = async (): Promise<unknown> => {
        switch (url) {
          case 'https://api.test/auth/reg/options':
            return {
              publicKey: await server.generateRegistrationOptions({
                user: { name: String(body.username) },
                sessionKey: 's',
              }),
            };
          case 'https://api.test/auth/reg/verify': {
            const { credential } = await server.verifyRegistration({
              response: body.response as never,
              sessionKey: 's',
            });
            credentials.set(credential.id, credential);
            return { ok: true };
          }
          case 'https://api.test/auth/login/options':
            return server.generateAuthenticationOptions({ sessionKey: 's' });
          case 'https://api.test/auth/login/verify': {
            const response = body.response as AuthenticationResponseJSON;
            const r = await server.verifyAuthentication({
              response,
              sessionKey: 's',
              credential: credentials.get(response.id)!,
            });
            return { ok: true, counter: r.newCounter };
          }
          default:
            throw new Error(`unexpected ${url}`);
        }
      };
      const data = await json();
      return { ok: true, status: 200, json: () => Promise.resolve(data) };
    };

    const client = createWebAuthnClient({
      baseUrl: 'https://api.test/auth/',
      endpoints: {
        registrationOptions: '/reg/options',
        registrationVerify: '/reg/verify',
        authenticationOptions: '/login/options',
        authenticationVerify: '/login/verify',
      },
      fetch: fetchMock,
      headers: () => ({ 'X-CSRF-Token': 'token' }),
    });

    await expect(client.register({ username: 'carol' })).resolves.toEqual({ ok: true });
    await expect(client.authenticate()).resolves.toEqual({ ok: true, counter: 1 });
    expect(seen).toHaveLength(4);
    expect(seen[0]!.headers['X-CSRF-Token']).toBe('token');
  });

  it('surfaces HTTP and network failures as NETWORK_ERROR', async () => {
    installBrowser(await SoftAuthenticator.create());
    const failing = createWebAuthnClient({
      fetch: () =>
        Promise.resolve({
          ok: false,
          status: 403,
          json: () => Promise.resolve({ message: 'forbidden' }),
        }),
    });
    await expect(failing.register()).rejects.toMatchObject({
      code: 'NETWORK_ERROR',
      message: expect.stringContaining('forbidden') as string,
    });
    const offline = createWebAuthnClient({
      fetch: () => Promise.reject(new TypeError('offline')),
    });
    await expect(offline.authenticate()).rejects.toMatchObject({ code: 'NETWORK_ERROR' });
    const garbage = createWebAuthnClient({
      fetch: () =>
        Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) }),
    });
    await expect(garbage.authenticate()).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

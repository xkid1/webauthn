// A relying party built the way the README tells developers to: one
// createWebAuthnServer at boot, a challenge store, credentials persisted as JSON.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import {
  createWebAuthnServer,
  isWebAuthnError,
  MemoryChallengeStore,
} from '@xkid1/webauthn/server';

import { ALG, SoftAuthenticator } from './fixtures/authenticator.mjs';

const ORIGIN = 'https://example.com';

function makeServer(overrides = {}) {
  return createWebAuthnServer({
    rpId: 'example.com',
    rpName: 'Example',
    origins: [ORIGIN],
    challengeStore: new MemoryChallengeStore(),
    ...overrides,
  });
}

/** Simulate a database: persist exactly what the README says to store, as JSON. */
const db = new Map();
const save = (key, value) => db.set(key, JSON.stringify(value));
const load = (key) => JSON.parse(db.get(key));

async function register(server, authenticator, sessionKey) {
  const options = await server.generateRegistrationOptions({
    user: { name: `${sessionKey}@example.com`, displayName: sessionKey },
    sessionKey,
  });
  const response = authenticator.register(options, { origin: ORIGIN });
  return server.verifyRegistration({ response, sessionKey });
}

async function signIn(server, authenticator, sessionKey, stored) {
  const options = await server.generateAuthenticationOptions({
    allowCredentials: [{ id: stored.id, transports: stored.transports }],
    sessionKey,
  });
  const response = authenticator.authenticate(options, { origin: ORIGIN });
  return server.verifyAuthentication({ response, sessionKey, credential: stored });
}

describe('server: register and sign in', () => {
  for (const [name, alg] of Object.entries(ALG)) {
    test(`${name} passkey: registration, persistence and two sign-ins`, async () => {
      const server = makeServer();
      const authenticator = new SoftAuthenticator(alg);
      const sessionKey = `user-${name}`;

      const registration = await register(server, authenticator, sessionKey);
      assert.equal(registration.credential.id, authenticator.id);
      assert.equal(registration.credential.algorithm, alg);
      assert.equal(registration.userVerified, true);
      assert.deepEqual(registration.attestation, {
        format: 'none',
        type: 'none',
        trusted: false,
        trustPath: [],
      });

      // Persist the README's "what to store" fields, then reload them like a DB row.
      const { id, publicKey, counter, transports } = registration.credential;
      save(id, { id, publicKey, counter, transports });

      const first = await signIn(server, authenticator, sessionKey, load(id));
      assert.equal(first.credentialId, id);
      assert.equal(first.newCounter, 1);
      save(id, { ...load(id), counter: first.newCounter });

      const second = await signIn(server, authenticator, sessionKey, load(id));
      assert.equal(second.newCounter, 2);
    });
  }
});

describe('server: developer-facing errors', () => {
  test('misconfiguration fails at boot with a hint', () => {
    assert.throws(
      () =>
        createWebAuthnServer({
          rpId: 'https://example.com',
          rpName: 'x',
          origins: [ORIGIN],
        }),
      (error) => {
        assert.ok(isWebAuthnError(error, 'INVALID_CONFIG'));
        assert.match(error.hint, /rpId/u);
        return true;
      },
    );
  });

  test('wrong origin: code, message, hint and a safe JSON body', async () => {
    const server = makeServer();
    const authenticator = new SoftAuthenticator();
    const options = await server.generateRegistrationOptions({
      user: { name: 'eve' },
      sessionKey: 'eve',
    });
    const response = authenticator.register(options, {
      origin: 'https://evil.example.org',
    });

    await assert.rejects(
      server.verifyRegistration({ response, sessionKey: 'eve' }),
      (error) => {
        assert.ok(isWebAuthnError(error, 'ORIGIN_MISMATCH'));
        const body = JSON.parse(JSON.stringify(error));
        assert.deepEqual(Object.keys(body).sort(), ['code', 'hint', 'message', 'name']);
        assert.equal(body.code, 'ORIGIN_MISMATCH');
        assert.match(body.hint, /origins/u);
        assert.doesNotMatch(
          JSON.stringify(body),
          new RegExp(options.challenge, 'u'),
          'no challenge leak',
        );
        assert.match(String(error), /^WebAuthnError \[ORIGIN_MISMATCH\]: .+ Hint: /u);
        return true;
      },
    );
  });

  test('a challenge cannot be replayed', async () => {
    const server = makeServer();
    const authenticator = new SoftAuthenticator();
    const options = await server.generateRegistrationOptions({
      user: { name: 'bob' },
      sessionKey: 'bob',
    });
    const response = authenticator.register(options, { origin: ORIGIN });
    await server.verifyRegistration({ response, sessionKey: 'bob' });
    await assert.rejects(
      server.verifyRegistration({ response, sessionKey: 'bob' }),
      (error) => isWebAuthnError(error, 'CHALLENGE_NOT_FOUND'),
    );
  });

  test('a forged signature is rejected', async () => {
    const server = makeServer();
    const authenticator = new SoftAuthenticator();
    const { credential } = await register(server, authenticator, 'carol');
    const options = await server.generateAuthenticationOptions({ sessionKey: 'carol' });
    const response = authenticator.authenticate(options, { origin: ORIGIN });
    const signature = Buffer.from(response.response.signature, 'base64url');
    signature[signature.length - 1] ^= 0x01;
    response.response.signature = signature.toString('base64url');

    await assert.rejects(
      server.verifyAuthentication({ response, sessionKey: 'carol', credential }),
      (error) => isWebAuthnError(error, 'SIGNATURE_INVALID'),
    );
  });

  test('a cloned authenticator (counter regression) is detected', async () => {
    const server = makeServer();
    const authenticator = new SoftAuthenticator();
    const { credential } = await register(server, authenticator, 'dave');
    const stored = { ...credential, counter: 10 };
    await assert.rejects(signIn(server, authenticator, 'dave', stored), (error) =>
      isWebAuthnError(error, 'COUNTER_REGRESSION'),
    );
  });
});

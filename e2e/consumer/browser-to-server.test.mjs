// Full stack: a real HTTP backend (node:http + @xkid1/webauthn/server) and a
// "browser" using @xkid1/webauthn/client's createWebAuthnClient with real fetch.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { after, before, describe, test } from 'node:test';

import { createWebAuthnClient, isWebAuthnError } from '@xkid1/webauthn/client';
import { createWebAuthnServer, MemoryChallengeStore } from '@xkid1/webauthn/server';

import { SoftAuthenticator } from './fixtures/authenticator.mjs';
import { installBrowser } from './fixtures/browser.mjs';

/** A minimal passkey backend using the default client endpoints. */
function startBackend() {
  const users = new Map(); // username → { id, credentials: Map<credentialId, stored> }
  let webauthn;

  const routes = {
    async '/webauthn/register/options'({ username }) {
      return webauthn.generateRegistrationOptions({
        user: { name: username },
        excludeCredentials: [...(users.get(username)?.credentials.values() ?? [])],
        sessionKey: username,
      });
    },
    async '/webauthn/register/verify'({ username, response }) {
      const { credential } = await webauthn.verifyRegistration({
        response,
        sessionKey: username,
      });
      const user = users.get(username) ?? { credentials: new Map() };
      user.credentials.set(credential.id, {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports,
      });
      users.set(username, user);
      return { verified: true, credentialId: credential.id };
    },
    async '/webauthn/authenticate/options'({ username }) {
      return webauthn.generateAuthenticationOptions({
        allowCredentials: [...(users.get(username)?.credentials.values() ?? [])],
        sessionKey: username,
      });
    },
    async '/webauthn/authenticate/verify'({ username, response }) {
      const stored = users.get(username)?.credentials.get(response.id);
      if (!stored) return { status: 404, body: { message: 'Unknown credential' } };
      const result = await webauthn.verifyAuthentication({
        response,
        sessionKey: username,
        credential: stored,
      });
      stored.counter = result.newCounter;
      return { verified: true, counter: result.newCounter };
    },
  };

  const server = createServer(async (req, res) => {
    let status = 200;
    let body;
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const route = routes[req.url];
      if (!route) throw Object.assign(new Error('Not found'), { status: 404 });
      const result = await route(
        JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'),
      );
      if (result && 'status' in result) ({ status, body } = result);
      else body = result;
    } catch (error) {
      // Recommended pattern: return the library's safe JSON view to the client.
      status = isWebAuthnError(error) ? 400 : (error.status ?? 500);
      body = isWebAuthnError(error) ? error.toJSON() : { message: error.message };
    }
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  });

  return new Promise((resolve) => {
    server.listen(0, 'localhost', () => {
      const origin = `http://localhost:${server.address().port}`;
      webauthn = createWebAuthnServer({
        rpId: 'localhost',
        rpName: 'E2E',
        origins: [origin],
        challengeStore: new MemoryChallengeStore(),
      });
      resolve({
        origin,
        close: () =>
          new Promise((done) => {
            server.close(done);
          }),
      });
    });
  });
}

describe('browser → HTTP → server', () => {
  let backend;
  before(async () => {
    backend = await startBackend();
  });
  after(() => backend.close());

  test('a user registers a passkey and signs in twice', async () => {
    const restore = installBrowser(new SoftAuthenticator(), { origin: backend.origin });
    try {
      const client = createWebAuthnClient({ baseUrl: backend.origin });
      const registered = await client.register({ username: 'alice' });
      assert.equal(registered.verified, true);

      assert.deepEqual(await client.authenticate({ username: 'alice' }), {
        verified: true,
        counter: 1,
      });
      assert.deepEqual(await client.authenticate({ username: 'alice' }), {
        verified: true,
        counter: 2,
      });
    } finally {
      restore();
    }
  });

  test('a phishing origin is rejected and the developer gets an actionable error', async () => {
    const authenticator = new SoftAuthenticator();
    const restoreGood = installBrowser(authenticator, { origin: backend.origin });
    const client = createWebAuthnClient({ baseUrl: backend.origin });
    await client.register({ username: 'bob' });
    restoreGood();

    // Same authenticator, but the page asking for the assertion is a look-alike site.
    const restore = installBrowser(authenticator, { origin: 'https://examp1e.com' });
    try {
      await assert.rejects(client.authenticate({ username: 'bob' }), (error) => {
        assert.ok(isWebAuthnError(error, 'NETWORK_ERROR'));
        assert.equal(error.cause.code, 'ORIGIN_MISMATCH');
        assert.match(error.cause.hint, /origins/u);
        return true;
      });
    } finally {
      restore();
    }
  });

  test('network failures surface as NETWORK_ERROR with a hint', async () => {
    const restore = installBrowser(new SoftAuthenticator(), { origin: backend.origin });
    try {
      const client = createWebAuthnClient({ baseUrl: 'http://localhost:1' });
      await assert.rejects(client.register({ username: 'carol' }), (error) => {
        assert.ok(isWebAuthnError(error, 'NETWORK_ERROR'));
        assert.match(error.hint, /endpoint/u);
        return true;
      });
    } finally {
      restore();
    }
  });
});

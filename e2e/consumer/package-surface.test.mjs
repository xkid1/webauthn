// The installed package exposes exactly the documented entry points, has no
// dependencies, and is safe to import on a server (SSR) with no browser globals.
import assert from 'node:assert/strict';
import { existsSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { test } from 'node:test';

const require = createRequire(import.meta.url);

test('every documented entry point loads', async () => {
  const root = await import('@xkid1/webauthn');
  const client = await import('@xkid1/webauthn/client');
  const server = await import('@xkid1/webauthn/server');
  const android = await import('@xkid1/webauthn/android');

  for (const name of [
    'startRegistration',
    'startAuthentication',
    'createWebAuthnClient',
    'isWebAuthnSupported',
  ]) {
    assert.equal(typeof client[name], 'function', `client.${name}`);
  }
  for (const name of [
    'createWebAuthnServer',
    'MemoryChallengeStore',
    'generateRegistrationOptions',
    'verifyRegistrationResponse',
    'generateAuthenticationOptions',
    'verifyAuthenticationResponse',
    'createAndroidKeyVerifier',
    'createAndroidSafetyNetVerifier',
  ]) {
    assert.equal(typeof server[name], 'function', `server.${name}`);
  }
  for (const name of [
    'createAndroidPasskeyClient',
    'androidOriginFromFingerprint',
    'buildAssetLinks',
  ]) {
    assert.equal(typeof android[name], 'function', `android.${name}`);
  }
  for (const entry of [root, client, server, android]) {
    assert.equal(typeof entry.WebAuthnError, 'function');
    assert.equal(typeof entry.isWebAuthnError, 'function');
    assert.equal(typeof entry.getErrorHint, 'function');
  }
  for (const name of [
    'COSEAlgorithm',
    'decodeCbor',
    'encodeCbor',
    'parseAuthenticatorData',
    'createWebAuthnServer',
  ]) {
    assert.ok(name in root, `root.${name}`);
  }
});

test('WebAuthnError is the same class from every entry point', async () => {
  const [root, client, server, android] = await Promise.all([
    import('@xkid1/webauthn'),
    import('@xkid1/webauthn/client'),
    import('@xkid1/webauthn/server'),
    import('@xkid1/webauthn/android'),
  ]);
  assert.equal(client.WebAuthnError, root.WebAuthnError);
  assert.equal(server.WebAuthnError, root.WebAuthnError);
  assert.equal(android.WebAuthnError, root.WebAuthnError);
});

test('internal files are not importable (exports map is enforced)', async () => {
  await assert.rejects(import('@xkid1/webauthn/dist/index.js'), {
    code: 'ERR_PACKAGE_PATH_NOT_EXPORTED',
  });
  await assert.rejects(import('@xkid1/webauthn/src/index'), {
    code: 'ERR_PACKAGE_PATH_NOT_EXPORTED',
  });
});

test('the published package has zero dependencies and ships no tests or sources', () => {
  const pkg = require('@xkid1/webauthn/package.json');
  assert.equal(pkg.name, '@xkid1/webauthn');
  assert.deepEqual(Object.keys(pkg.dependencies ?? {}), []);
  assert.deepEqual(Object.keys(pkg.peerDependencies ?? {}), []);
  assert.equal(pkg.type, 'module');

  const dir = dirname(require.resolve('@xkid1/webauthn/package.json'));
  const files = readdirSync(dir, { recursive: true }).map(String);
  assert.ok(!existsSync(join(dir, 'src')), 'src/ must not be published');
  assert.ok(!existsSync(join(dir, 'node_modules')), 'no bundled dependencies');
  assert.deepEqual(
    files.filter((f) => /\.(test|spec|bench)\.[cm]?[jt]s$/u.test(f)),
    [],
    'no test files',
  );
});

test('client entry is SSR-safe: importing and feature checks work without a browser', async () => {
  assert.equal(globalThis.PublicKeyCredential, undefined);
  const client = await import('@xkid1/webauthn/client');
  assert.equal(client.isWebAuthnSupported(), false);
  await assert.rejects(client.startRegistration({ optionsJSON: {} }), (error) => {
    assert.ok(client.isWebAuthnError(error));
    assert.equal(typeof error.hint, 'string');
    return true;
  });
});

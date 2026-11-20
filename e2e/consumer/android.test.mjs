// A React Native / Android app talking to a Credential Manager bridge, plus the
// server-side setup (APK origin and assetlinks.json) a developer must do.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';

import {
  androidOriginFromFingerprint,
  buildAssetLinks,
  createAndroidPasskeyClient,
  isWebAuthnError,
} from '@xkid1/webauthn/android';
import { createWebAuthnServer } from '@xkid1/webauthn/server';

import { SoftAuthenticator } from './fixtures/authenticator.mjs';

// SHA-256 of a (fake) signing certificate, formatted like `keytool -list -v`.
const FINGERPRINT = createHash('sha256')
  .update(randomBytes(64))
  .digest('hex')
  .toUpperCase()
  .match(/../gu)
  .join(':');

test('assetlinks.json and the APK origin are derived from the signing fingerprint', () => {
  const origin = androidOriginFromFingerprint(FINGERPRINT);
  assert.match(origin, /^android:apk-key-hash:[A-Za-z0-9_-]{43}$/u);

  const statements = buildAssetLinks([
    { packageName: 'com.example.app', sha256CertFingerprints: [FINGERPRINT] },
  ]);
  assert.equal(statements[0].target.package_name, 'com.example.app');
  assert.deepEqual(statements[0].target.sha256_cert_fingerprints, [FINGERPRINT]);
  assert.ok(
    statements[0].relation.includes('delegate_permission/common.get_login_creds'),
  );
});

test('an Android app registers and signs in through the Credential Manager bridge', async () => {
  const origin = androidOriginFromFingerprint(FINGERPRINT);
  const server = createWebAuthnServer({
    rpId: 'example.com',
    rpName: 'Example',
    origins: [origin],
  });
  const authenticator = new SoftAuthenticator();

  // What a native module typically hands to JavaScript: JSON strings.
  const bridge = {
    createCredential: async (requestJson) =>
      JSON.stringify(authenticator.register(JSON.parse(requestJson), { origin })),
    getCredential: async (requestJson) =>
      JSON.stringify(authenticator.authenticate(JSON.parse(requestJson), { origin })),
    isAvailable: async () => true,
  };
  const passkeys = createAndroidPasskeyClient(bridge);
  assert.equal(await passkeys.isAvailable(), true);

  const regOptions = await server.generateRegistrationOptions({ user: { name: 'dana' } });
  const registration = await server.verifyRegistration({
    response: await passkeys.startRegistration({ optionsJSON: regOptions }),
    expectedChallenge: regOptions.challenge,
  });
  assert.equal(registration.origin, origin);

  const authOptions = await server.generateAuthenticationOptions();
  const result = await server.verifyAuthentication({
    response: await passkeys.startAuthentication({ optionsJSON: authOptions }),
    expectedChallenge: authOptions.challenge,
    credential: registration.credential,
  });
  assert.equal(result.newCounter, 1);
});

test('a cancelled Credential Manager prompt maps to a stable error code', async () => {
  const bridge = {
    createCredential: async () => {
      throw Object.assign(new Error('User cancelled'), {
        type: 'androidx.credentials.exceptions.CreateCredentialCancellationException',
      });
    },
    getCredential: async () => '{}',
  };
  const passkeys = createAndroidPasskeyClient(bridge);
  await assert.rejects(
    passkeys.startRegistration({ optionsJSON: { challenge: 'AAAA' } }),
    (error) => {
      assert.ok(isWebAuthnError(error, 'CEREMONY_NOT_ALLOWED'));
      assert.match(error.hint, /retry/u);
      return true;
    },
  );
});

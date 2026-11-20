# @xkid1/webauthn

[![CI](https://github.com/xkid1/webauthn/actions/workflows/ci.yml/badge.svg)](https://github.com/xkid1/webauthn/actions/workflows/ci.yml)
[![Build](https://github.com/xkid1/webauthn/actions/workflows/build.yml/badge.svg)](https://github.com/xkid1/webauthn/actions/workflows/build.yml)
[![Tests](https://github.com/xkid1/webauthn/actions/workflows/test.yml/badge.svg)](https://github.com/xkid1/webauthn/actions/workflows/test.yml)
[![E2E](https://github.com/xkid1/webauthn/actions/workflows/e2e.yml/badge.svg)](https://github.com/xkid1/webauthn/actions/workflows/e2e.yml)
[![CodeQL](https://github.com/xkid1/webauthn/actions/workflows/codeql.yml/badge.svg)](https://github.com/xkid1/webauthn/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/xkid1/webauthn/badge)](https://scorecard.dev/viewer/?uri=github.com/xkid1/webauthn)
[![Release](https://github.com/xkid1/webauthn/actions/workflows/publish.yml/badge.svg)](https://github.com/xkid1/webauthn/actions/workflows/publish.yml)
<br />
[![npm](https://img.shields.io/npm/v/@xkid1/webauthn?logo=npm&label=npm&color=e05d44)](https://www.npmjs.com/package/@xkid1/webauthn)
[![GitHub Packages](https://img.shields.io/badge/npm-xkid1-e05d44?logo=github)](https://github.com/xkid1/webauthn/pkgs/npm/webauthn)
[![license](https://img.shields.io/npm/l/@xkid1/webauthn?color=007ec6)](./LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-0-44cc11)](./package.json)
[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-ffdd00?logo=buymeacoffee&logoColor=black)](https://www.buymeacoffee.com/elmeralluaj)

[![Node.js](https://img.shields.io/badge/Node.js-20%20%7C%2022%20%7C%2024%20%7C%2026-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-types%20included-3178c6?logo=typescript&logoColor=white)](./src/types)
[![WebAuthn](https://img.shields.io/badge/WebAuthn-Level%203-5a29e4?logo=webauthn&logoColor=white)](https://w3c.github.io/webauthn/)
[![browser](https://img.shields.io/badge/browser-Chromium%20%7C%20Firefox%20%7C%20WebKit-4285f4?logo=googlechrome&logoColor=white)](#2-browser)
[![Deno](https://img.shields.io/badge/Deno-supported-000000?logo=deno&logoColor=white)](https://deno.com/)
[![Bun](https://img.shields.io/badge/Bun-supported-000000?logo=bun&logoColor=white)](https://bun.sh/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-supported-f38020?logo=cloudflareworkers&logoColor=white)](https://workers.cloudflare.com/)
[![Electron](https://img.shields.io/badge/Electron-24%2B-47848f?logo=electron&logoColor=white)](#framework-recipes)
[![React Native](https://img.shields.io/badge/React%20Native-Android-3ddc84?logo=android&logoColor=white)](#framework-recipes)
<br />
[![React](https://img.shields.io/badge/React-supported-20232a?logo=react&logoColor=61dafb)](#framework-recipes)
[![Next.js](https://img.shields.io/badge/Next.js-supported-000000?logo=nextdotjs&logoColor=white)](#framework-recipes)
[![Vue](https://img.shields.io/badge/Vue-supported-4fc08d?logo=vuedotjs&logoColor=white)](#framework-recipes)
[![Nuxt](https://img.shields.io/badge/Nuxt-supported-00dc82?logo=nuxt&logoColor=white)](#framework-recipes)
[![Angular](https://img.shields.io/badge/Angular-supported-dd0031?logo=angular&logoColor=white)](#framework-recipes)
[![Svelte](https://img.shields.io/badge/Svelte-supported-ff3e00?logo=svelte&logoColor=white)](#framework-recipes)
[![Solid](https://img.shields.io/badge/Solid-supported-2c4f7c?logo=solid&logoColor=white)](#framework-recipes)
[![module](https://img.shields.io/badge/module-ESM-007ec6)](./package.json)
[![tree-shakeable](https://img.shields.io/badge/tree--shakeable-yes-44cc11)](#size-and-cross-runtime-performance)

Zero-dependency, security-first **WebAuthn / passkeys** for every runtime: browsers, Node.js, Electron, React Native (Android) and edge workers. Written in strict TypeScript.

- **Zero runtime dependencies.** It ships its own CBOR, COSE, ASN.1/X.509, base64url and UTF-8 code, built only on WebCrypto.
- **Small and tree-shakeable.** It is pure ESM with `sideEffects: false` and separate `/client`, `/server` and `/android` entry points. The client entry is about 10 kB gzipped.
- **Secure by default.** It enforces exact origin allowlists, checks challenges in constant time, and makes every challenge single-use. It checks the RP ID hash, UP/UV and BE/BS flags, the algorithm allowlist, signature counters (clone detection) and the 1023-byte credential-ID limit. Its parsers have bounds checks, depth limits and length-bomb protection.
- **Customisable.** Every setting has a safe default you can override: algorithms, UV policy, attestation policy and trust anchors, counter policy, timeouts, cross-origin rules, plug-in attestation verifiers, an injectable WebCrypto and clock, a custom challenge store, and custom fetch, endpoints and headers.
- **Up to date with WebAuthn Level 3.** It supports JSON serialisation, `hints`, conditional mediation (passkey autofill), conditional create (auto-register), `getClientCapabilities()` and the Signal API.
- **Framework-agnostic and SSR-safe.** It works with React, Next.js, Vue, Nuxt, Angular, Svelte/SvelteKit, Solid, Electron and React Native. Importing it never touches `window`.

---

## Install

```bash
yarn add @xkid1/webauthn
# or: npm i @xkid1/webauthn  /  pnpm add @xkid1/webauthn
```

Requirements: Node ≥ 20 on the server (any runtime with `globalThis.crypto` works) and any evergreen browser on the client.

| Entry point                | Use it in                                                       |
| -------------------------- | --------------------------------------------------------------- |
| `@xkid1/webauthn/client`   | Browser, Electron renderer, WebView                             |
| `@xkid1/webauthn/server`   | Node, Deno, Bun, Cloudflare Workers, Electron main              |
| `@xkid1/webauthn/android`  | React Native / native Android (Credential Manager bridge)       |
| `@xkid1/webauthn`          | Everything, plus low-level parsers (`decodeCbor`, `parseCoseKey`…) |

---

## Quick start

### 1. Server

```ts
import { createWebAuthnServer, MemoryChallengeStore } from '@xkid1/webauthn/server';

export const webauthn = createWebAuthnServer({
  rpId: 'example.com',
  rpName: 'Example Inc.',
  origins: ['https://example.com'],          // exact match, no wildcards
  challengeStore: new MemoryChallengeStore(), // use Redis/DB in multi-instance deployments
});

// POST /webauthn/register/options
app.post('/webauthn/register/options', async (req, res) => {
  const user = req.session.user;
  res.json(
    await webauthn.generateRegistrationOptions({
      user: { id: user.webauthnId, name: user.email, displayName: user.name }, // id: random bytes, never PII
      excludeCredentials: await db.credentials.listFor(user.id),
      sessionKey: req.session.id,
    }),
  );
});

// POST /webauthn/register/verify
app.post('/webauthn/register/verify', async (req, res) => {
  const { credential } = await webauthn.verifyRegistration({
    response: req.body.response,
    sessionKey: req.session.id,
  });
  await db.credentials.insert({ userId: req.session.user.id, ...credential });
  res.json({ ok: true });
});

// POST /webauthn/authenticate/options
app.post('/webauthn/authenticate/options', async (req, res) => {
  res.json(await webauthn.generateAuthenticationOptions({ sessionKey: req.session.id }));
});

// POST /webauthn/authenticate/verify
app.post('/webauthn/authenticate/verify', async (req, res) => {
  const stored = await db.credentials.findById(req.body.response.id);
  if (!stored) return res.status(401).json({ message: 'Unknown credential' });

  const result = await webauthn.verifyAuthentication({
    response: req.body.response,
    sessionKey: req.session.id,
    credential: stored,
    expectedUserHandle: stored.userWebauthnId,
  });
  await db.credentials.update(stored.id, { counter: result.newCounter, backedUp: result.backedUp });
  req.session.userId = stored.userId;
  res.json({ ok: true });
});
```

If you prefer to manage challenges yourself, pass `expectedChallenge` instead of `sessionKey`.

### 2. Browser

```ts
import { createWebAuthnClient, isWebAuthnSupported } from '@xkid1/webauthn/client';

const passkeys = createWebAuthnClient({
  headers: () => ({ 'X-CSRF-Token': getCsrfToken() }),
});

if (isWebAuthnSupported()) {
  await passkeys.register();      // create a passkey
  await passkeys.authenticate();  // sign in with it
}
```

Or use the low-level calls with your own HTTP layer:

```ts
import { startRegistration, startAuthentication } from '@xkid1/webauthn/client';

const optionsJSON = await api.post('/webauthn/register/options');
const response = await startRegistration({ optionsJSON });
await api.post('/webauthn/register/verify', { response });
```

### What to store per credential

`verifyRegistration` returns a `RegisteredCredential`. Store at least `id`, `publicKey`, `counter` and `transports`. Storing `deviceType`, `backedUp`, `aaguid` and `createdAt` is also useful. All values are JSON- and DB-friendly strings, numbers and booleans.

---

## Configuration

| Option                      | Default                    | Notes |
| --------------------------- | -------------------------- | ----- |
| `rpId`                      | required                   | Domain only (`example.com`). Validated. |
| `rpName`                    | required                   | Shown by some authenticators. |
| `origins`                   | required                   | Exact allowlist. `https://…`, `http://localhost…`, `android:apk-key-hash:…`. Each web origin must sit within `rpId`. |
| `timeout`                   | `300000`                   | ms; also the challenge TTL in the store (10 s – 10 min). |
| `userVerification`          | `'preferred'`              | What is requested from the authenticator. |
| `requireUserVerification`   | `userVerification === 'required'` | What the server **enforces** (UV flag). |
| `attestation`               | `'none'`                   | Privacy-friendly; recommended unless you need device provenance. |
| `supportedAlgorithms`       | `[-8, -7, -257]`           | EdDSA, ES256, RS256. ES384/512, PS256/384/512 and Ed25519 (-19) are also supported. RS1 is never accepted. |
| `authenticatorSelection`    | `{ residentKey: 'preferred' }` | Merged per ceremony. |
| `hints`                     | `[]`                       | `'security-key' \| 'client-device' \| 'hybrid'`. |
| `challengeSize`             | `32`                       | Bytes, 16–64. |
| `allowCrossOrigin`          | `false`                    | Needs `allowedTopOrigins`. |
| `counterPolicy`             | `'strict'`                 | `'lenient'` returns `counterWarning: true` instead of throwing. |
| `attestationVerifiers`      | all WebAuthn L3 formats (see below) | Add vendor formats, or override a built-in by `fmt`. |
| `trustAnchors`              | `[]`                       | DER root certificates for attestation chains. |
| `requireTrustedAttestation` | `false`                    | Reject registrations that do not chain to `trustAnchors`. |
| `crypto`                    | `globalThis.crypto`        | Inject WebCrypto (for example `webcrypto` from `node:crypto`). |
| `now`                       | `Date.now`                 | Clock injection for tests. |

### Supported attestation formats

Every statement format defined in [WebAuthn Level 3 §8](https://w3c.github.io/webauthn/#sctn-defined-attestation-formats) is verified out of the box:

| `fmt`               | Spec  | Attestation type      | Notes |
| ------------------- | ----- | --------------------- | ----- |
| `packed`            | §8.2  | `basic` / `self`      | x5c and self attestation. ECDAA is rejected. |
| `tpm`               | §8.3  | `attca`               | TPM 2.0 `pubArea` / `certInfo` checks and AIK certificate profile (empty subject, critical SAN with TPM device attributes, `tcg-kp-AIKCertificate` EKU). SHA-1 name algorithms and RS1 signatures are rejected. ECDAA is rejected. |
| `android-key`       | §8.4  | `basic`               | Checks the KeyDescription extension: challenge, no `allApplications`, `KM_ORIGIN_GENERATED` and `KM_PURPOSE_SIGN`. |
| `android-safetynet` | §8.5  | `basic`               | JWS signature, nonce, `ctsProfileMatch`, and a leaf issued to `attest.android.com`. Responses older than 60 s are rejected. (Google has deprecated SafetyNet.) |
| `fido-u2f`          | §8.6  | `basic`               | Legacy U2F security keys. |
| `none`              | §8.7  | `none`                | Default. |
| `apple`             | §8.8  | `anonca`              | Nonce extension and credential-key binding. |

Signature and binding checks never depend on trust anchors. A chain is reported as `trusted: true` only when it terminates at one of your `trustAnchors`, for example the Apple WebAuthn Root CA, Google Hardware Attestation roots, GlobalSign for SafetyNet, TPM vendor roots, or roots from FIDO MDS.

> **Always decide on `trusted`, never on `type`.** An untrusted result still reports `basic`, `attca` or `anonca`. An `apple` statement carries no signature, so anyone can produce an untrusted one.
>
> **`trustAnchors` apply to every format.** If you add a public WebPKI root (for example GlobalSign to accept SafetyNet), any `packed`, `tpm` or other chain to that root that meets the format's certificate rules is also reported as trusted. Add only the anchors you need. If you require strict per-format anchors, register a wrapper verifier that passes its own anchors: `const sn = createAndroidSafetyNetVerifier();` then `attestationVerifiers: { 'android-safetynet': (ctx) => sn({ ...ctx, trustAnchors: [globalSign] }) }`. Keep that root out of the global `trustAnchors`.
>
> **Known limits.** There is no revocation checking. Leaked Android keyboxes are common, so check Google's attestation revocation list or FIDO MDS yourself. The SafetyNet `ver` value is required but not matched against a list of known versions. A TPM AIK with no Basic Constraints extension is treated as a non-CA, and its manufacturer ID is checked for format only, not against the TCG vendor registry.

Two formats offer stricter, opt-in variants:

```ts
import { createAndroidKeyVerifier, createAndroidSafetyNetVerifier } from '@xkid1/webauthn/server';

createWebAuthnServer({
  /* … */
  attestation: 'direct',
  attestationVerifiers: {
    // Only accept keys whose origin/purpose is enforced by the TEE or StrongBox.
    'android-key': createAndroidKeyVerifier({ requireTeeEnforced: true }),
    // Freshness window for SafetyNet responses (defaults: 60 000 ms max age, 0 ms future skew).
    'android-safetynet': createAndroidSafetyNetVerifier({ maxAgeMs: 30_000 }),
  },
});
```

### Custom attestation formats

```ts
import type { AttestationVerifier } from '@xkid1/webauthn/server';

const vendor: AttestationVerifier = async (ctx) => {
  // ctx: { attStmt, authData, parsedAuthData, clientDataHash, crypto, trustAnchors, now }
  // …verify, then:
  return { type: 'basic', trustPath: [], trusted: true };
};

createWebAuthnServer({ /* … */, attestation: 'direct', attestationVerifiers: { 'vendor-fmt': vendor } });
```

### Custom challenge store (Redis example)

```ts
const redisStore: ChallengeStore = {
  set: (key, challenge, ttl) => redis.set(key, challenge, { PX: ttl }),
  take: async (key) => (await redis.getDel(key)) ?? undefined, // MUST delete: challenges are single-use
};
```

---

## Framework recipes

All recipes use `@xkid1/webauthn/client`. Call `cancelCeremony()` (or `client.cancel()`) when a view unmounts, so that a pending passkey-autofill request does not leak.

<details><summary><b>React / Next.js</b></summary>

```tsx
'use client';
import { useEffect } from 'react';
import { cancelCeremony, isConditionalMediationAvailable, startAuthentication } from '@xkid1/webauthn/client';

export function LoginForm() {
  useEffect(() => {
    void (async () => {
      if (!(await isConditionalMediationAvailable())) return;
      const optionsJSON = await fetch('/webauthn/authenticate/options', { method: 'POST' }).then((r) => r.json());
      const response = await startAuthentication({ optionsJSON, useBrowserAutofill: true }).catch(() => null);
      if (response) await fetch('/webauthn/authenticate/verify', { method: 'POST', body: JSON.stringify({ response }) });
    })();
    return cancelCeremony; // StrictMode-safe
  }, []);
  return <input name="username" autoComplete="username webauthn" />;
}
```
</details>

<details><summary><b>Vue 3 / Nuxt</b></summary>

```ts
// composables/usePasskeys.ts
import { onBeforeUnmount, ref } from 'vue';
import { createWebAuthnClient, isWebAuthnSupported, type WebAuthnError } from '@xkid1/webauthn/client';

export function usePasskeys() {
  const client = createWebAuthnClient();
  const error = ref<WebAuthnError | null>(null);
  onBeforeUnmount(client.cancel);
  const run = (fn: () => Promise<unknown>) => fn().catch((e) => (error.value = e));
  return {
    supported: isWebAuthnSupported(),
    error,
    register: () => run(() => client.register()),
    signIn: () => run(() => client.authenticate()),
  };
}
```
</details>

<details><summary><b>Angular</b></summary>

```ts
import { Injectable, inject, OnDestroy } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { createWebAuthnClient, type FetchLike } from '@xkid1/webauthn/client';

@Injectable({ providedIn: 'root' })
export class PasskeyService implements OnDestroy {
  private http = inject(HttpClient);
  private fetch: FetchLike = async (url, init) => {
    const data = await firstValueFrom(this.http.post(url, JSON.parse(init.body ?? '{}'), { withCredentials: true }));
    return { ok: true, status: 200, json: async () => data };
  };
  private client = createWebAuthnClient({ fetch: this.fetch }); // reuses interceptors (auth, CSRF)
  register = () => this.client.register();
  signIn = () => this.client.authenticate();
  ngOnDestroy() { this.client.cancel(); }
}
```
</details>

<details><summary><b>Svelte / SvelteKit</b></summary>

```svelte
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { browser } from '$app/environment';
  import { createWebAuthnClient } from '@xkid1/webauthn/client';
  const client = createWebAuthnClient();
  onDestroy(client.cancel);
</script>

{#if browser}<button on:click={() => client.authenticate()}>Sign in with a passkey</button>{/if}
```
</details>

<details><summary><b>Electron</b></summary>

- **Renderer:** use `@xkid1/webauthn/client` as you would in a browser. WebAuthn needs a **secure origin**, so load your UI from `https://your-domain` (with `rpId` set to that domain) or from `http://localhost` during development. `file://` and custom protocols cannot use WebAuthn.
- **Main process:** you can run `@xkid1/webauthn/server` there (Node WebCrypto). Usually your backend verifies instead.
- Platform authenticators (Touch ID, Windows Hello) work in Electron ≥ 24 on macOS and Windows.
</details>

<details><summary><b>React Native (Android)</b></summary>

React Native has no `navigator.credentials`. Android passkeys go through **Jetpack Credential Manager**. This package handles the JS side: JSON normalisation (padded or standard base64, a missing `rawId`), validation, and error mapping. You provide a ~40-line native module.

```ts
import { NativeModules } from 'react-native';
import { createAndroidPasskeyClient } from '@xkid1/webauthn/android';

const passkeys = createAndroidPasskeyClient(NativeModules.Passkey); // { createCredential, getCredential }

const optionsJSON = await api.post('/webauthn/register/options');
const response = await passkeys.startRegistration({ optionsJSON });
await api.post('/webauthn/register/verify', { response });
```

Native module sketch (Kotlin, `androidx.credentials:credentials` + `credentials-play-services-auth`):

```kotlin
class PasskeyModule(ctx: ReactApplicationContext) : ReactContextBaseJavaModule(ctx) {
  private val cm = CredentialManager.create(ctx)
  override fun getName() = "Passkey"

  @ReactMethod fun createCredential(requestJson: String, promise: Promise) {
    val activity = currentActivity ?: return promise.reject("NoActivity", "No foreground activity")
    CoroutineScope(Dispatchers.Main).launch {
      try {
        val res = cm.createCredential(activity, CreatePublicKeyCredentialRequest(requestJson))
        promise.resolve((res as CreatePublicKeyCredentialResponse).registrationResponseJson)
      } catch (e: CreateCredentialException) { promise.reject(e.type, e.message, e) }
    }
  }

  @ReactMethod fun getCredential(requestJson: String, promise: Promise) {
    val activity = currentActivity ?: return promise.reject("NoActivity", "No foreground activity")
    CoroutineScope(Dispatchers.Main).launch {
      try {
        val req = GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson)))
        val cred = cm.getCredential(activity, req).credential as PublicKeyCredential
        promise.resolve(cred.authenticationResponseJson)
      } catch (e: GetCredentialException) { promise.reject(e.type, e.message, e) }
    }
  }
}
```

**Server setup for Android:**

```ts
import { androidOriginFromFingerprint, buildAssetLinks } from '@xkid1/webauthn/android';

const FP = 'FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C';

createWebAuthnServer({
  rpId: 'example.com',
  rpName: 'Example',
  origins: ['https://example.com', androidOriginFromFingerprint(FP)],
});

// Serve at https://example.com/.well-known/assetlinks.json
app.get('/.well-known/assetlinks.json', (_req, res) =>
  res.json(buildAssetLinks([{ packageName: 'com.example.app', sha256CertFingerprints: [FP] }])),
);
```

**iOS (React Native):** use a native bridge to `ASAuthorizationPlatformPublicKeyCredentialProvider`. Its responses use `https://<rpId>` origins, and the server side is identical.
</details>

---

## Errors

Every failure is a `WebAuthnError`. Each error has:

- `code`: stable and machine-readable. Switch on it, never on `message`.
- `message`: what went wrong.
- `hint`: how to fix or handle it, e.g. *"Add the exact origin (scheme, host and port) to config.origins"*.
- `cause` (optional): the underlying error, e.g. the browser's `DOMException`.

Messages and hints never contain challenges, keys, signatures or user handles, so they are safe to log. `error.toJSON()` returns `{ name, code, message, hint }`. It leaves out `cause` and the stack, so you can return it from an API.

```ts
import { isWebAuthnError } from '@xkid1/webauthn/client';

try { await passkeys.authenticate(); }
catch (e) {
  if (isWebAuthnError(e, 'CEREMONY_NOT_ALLOWED', 'CEREMONY_ABORTED')) return; // cancelled / timed out
  if (isWebAuthnError(e)) console.warn(String(e)); // "WebAuthnError [CODE]: message Hint: …"
  throw e;
}
```

```ts
// Server: return the safe JSON view to your client
catch (e) {
  if (isWebAuthnError(e)) return res.status(400).json(e.toJSON());
  throw e;
}
```

`getErrorHint(code)` and `ERROR_HINTS` give you the hint for any code, for example to build your own error pages.

| Group | Codes |
| --- | --- |
| Client ceremony | `CEREMONY_NOT_ALLOWED`, `CEREMONY_ABORTED`, `CREDENTIAL_EXCLUDED`, `SECURITY_ERROR`, `NOT_SUPPORTED`, `CONSTRAINT_ERROR`, `NETWORK_ERROR` |
| Client data | `TYPE_MISMATCH`, `CHALLENGE_MISMATCH`, `CHALLENGE_NOT_FOUND`, `ORIGIN_MISMATCH`, `CROSS_ORIGIN_NOT_ALLOWED`, `TOP_ORIGIN_MISMATCH` |
| Authenticator data | `RP_ID_MISMATCH`, `USER_PRESENCE_REQUIRED`, `USER_VERIFICATION_REQUIRED`, `INVALID_FLAGS`, `INVALID_AUTHENTICATOR_DATA` |
| Keys and signatures | `UNSUPPORTED_ALGORITHM`, `INVALID_PUBLIC_KEY`, `SIGNATURE_INVALID`, `COUNTER_REGRESSION` |
| Attestation | `ATTESTATION_INVALID`, `ATTESTATION_FORMAT_UNSUPPORTED`, `ATTESTATION_UNTRUSTED` |
| Input and config | `INVALID_INPUT`, `INVALID_CONFIG`, `ENCODING_ERROR`, `CBOR_ERROR`, `ASN1_ERROR`, `UNSUPPORTED_ENVIRONMENT`, `CREDENTIAL_ID_MISMATCH`, `CREDENTIAL_ID_TOO_LONG`, `USER_HANDLE_MISMATCH` |

On the server, return a generic 400/401 to the client and log the `code`.

---

## Security notes

- **Challenges** come from a CSPRNG (32 bytes by default), are compared in constant time, and are single-use through `ChallengeStore.take()`. Registration and authentication challenges are namespaced separately.
- **Origins** must match an exact allowlist. `http:` is allowed only for `localhost`.
- The **user handle** (`user.id`) is random by default. Never put an email address or other PII in it.
- **Attestation** defaults to `none`. All WebAuthn L3 formats (`packed`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `apple`) are verified, including X.509 chain validation against your `trustAnchors`: validity windows, issuer linkage, CA flag and signatures. Revocation (CRL/OCSP) and FIDO MDS lookups are out of scope; plug them in with `attestationVerifiers`.
- **Counters:** a counter that does not increase raises `COUNTER_REGRESSION`. Synced passkeys always report `0/0`, which is accepted.
- **Parsers** (CBOR, DER, authenticatorData, clientDataJSON) are strict. They reject trailing bytes, indefinite lengths, duplicate keys, non-canonical base64url and oversize input.

Report vulnerabilities privately; see [SECURITY.md](./SECURITY.md).

---

## Development

```bash
corepack enable
yarn install
yarn check          # typecheck + lint + format + tests
yarn test:coverage
yarn build          # swc (JS) + tsc (d.ts) + alias rewrite
yarn verify:dist    # no aliases, no bare imports, entry points load
yarn e2e            # build, pack, install into a fresh app, run it like a consumer
yarn bench          # micro-benchmarks on the TypeScript sources (Vitest bench)
yarn bench:size     # install + tree-shaken bundle size; add --check to enforce budgets
yarn bench:runtimes # speed + cold import of dist/ in Node, Bun, Deno and browsers
```

### Size and cross-runtime performance

`yarn bench:size` and `yarn bench:runtimes` measure the **built** package (`dist/`), so run `yarn build` first.

- **Size:** `bench/size.mjs` packs the package to report install size. It then bundles realistic imports with Rolldown (tree-shaken and minified) and reports raw, gzip and brotli sizes. CI runs it with `--check` against `bench/size-budget.json`, so a size regression fails the build. If you raise a budget deliberately, explain why in the PR.
- **Speed in every runtime:** `bench/runtimes.mjs` runs `bench/runtime/suite.js` in each runtime it finds, and skips the rest with a note. The suite is plain ESM that uses only WebCrypto, so the same code runs in Node, Bun (`bun`), Deno (`deno run`) and, through Playwright, in Chromium, Firefox and WebKit. It also times a cold `import()` of every entry point in fresh processes. You can open `bench/runtime/browser.html` from any static server at the repo root to run it in your own browser.
- **CI:** `.github/workflows/bench.yml` runs both on Node, Bun, Deno and the three browsers, manually or on pushes to `main`. It posts the tables to the job summary and uploads the JSON results.

Sample (Node 26, Linux x64; compare runs on the same machine, not across machines):

| | ops/s |
| --- | ---: |
| `verifyRegistrationResponse` ES256 / EdDSA / RS256 | ≈ 5,200 / 5,400 / 5,100 |
| `verifyAuthenticationResponse` ES256 / EdDSA / RS256 | ≈ 2,500 / 2,600 / 2,900 |
| `generateRegistrationOptions` | ≈ 300,000 |

| Import (tree-shaken, minified) | brotli |
| --- | ---: |
| `startRegistration` + `startAuthentication` | 4.2 kB |
| `createWebAuthnServer` + `MemoryChallengeStore` | 15.4 kB |
| `createAndroidPasskeyClient` | 3.4 kB |

**End-to-end tests (`e2e/`)** test the published package, not the source. `e2e/run.mjs` does the following:

1. Packs the build with `yarn pack`.
2. Installs the tarball into a new project in a temp directory with `npm install --offline`, which fails if the package has any dependency.
3. Runs the tests in `e2e/consumer/*.test.mjs` with `node --test`. They import only `@xkid1/webauthn`, `/client`, `/server` and `/android` and cover:
   - the export map, SSR-safe imports, and no tests or sources in the package;
   - registration and sign-in for ES256, EdDSA and RS256 with credentials persisted as JSON;
   - a real HTTP backend driven by `createWebAuthnClient` over `fetch`;
   - the Android Credential Manager bridge;
   - developer-facing errors (`code`, `hint`, `toJSON()`).
4. Type-checks `e2e/consumer/types/consumer.ts` with `NodeNext` and `Bundler` resolution, with `skipLibCheck: false` and no DOM or Node types.

The consumer tests use their own software authenticator built on `node:crypto` with a separate CBOR encoder, so the library never verifies data it encoded itself. Pass `--keep` (`node e2e/run.mjs --keep`) to keep the temp project for debugging.

**Benchmarks (`bench/`)** measure the following:

- encoding: base64url, CBOR, authenticatorData, clientDataJSON, COSE keys;
- options generation;
- registration and sign-in verification per algorithm;
- full registration verification for every attestation format.

Keys and responses are generated once up front, so each benchmark measures verification only. The benchmarks run on the TypeScript sources through Vitest's module runner, which adds a little per-call overhead (Vitest prints a warning about it). That matters for the sub-microsecond encoding numbers, but not for ceremony or attestation timings.

Project layout:

```
src/
├── apps/       client-side · server-side · android   (public entry points)
├── libs/       cbor · cose · crypto · asn1 · authenticator-data · client-data · attestation
├── utils/      helpers (base64url, bytes, utf8, crypto, guards, errors)
├── types/      all types, one folder per domain (no DOM / Node lib dependency)
└── index.ts
```

Import aliases: `@apps`, `@libs`, `@types`, `@utils`, one per layer barrel. Use relative imports inside a layer. The build rewrites aliases to relative paths, so the published package needs no resolver.

## License

MIT © xkid1

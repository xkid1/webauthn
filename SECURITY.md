# Security Policy

`@xkid1/webauthn` verifies authentication ceremonies, so a bug that lets a response pass when it should fail is a security bug. Thank you for helping keep the library and the people who rely on it safe.

## Reporting a vulnerability

Please **do not** open a public issue, discussion or pull request.

Report privately through GitHub instead: open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to <https://github.com/xkid1/webauthn/security/advisories/new>.

A useful report includes:

- the affected version (`npm ls @xkid1/webauthn`) and entry point (`/server`, `/client`, `/android` or `.`)
- the runtime (Node, Bun, Deno, browser, React Native) and its version
- a minimal reproduction, ideally a crafted response or byte sequence and the `verifyRegistration` / `verifyAuthentication` config you used
- what you expected to happen and what actually happened
- the impact as you understand it, such as authentication bypass, credential confusion or denial of service

Use test credentials only. Never send real user handles, private keys or session tokens.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement | within 72 hours |
| Initial assessment and severity | within 7 days |
| Fix released for confirmed issues | as fast as the severity requires, normally within 30 days |
| Public advisory | when the fixed version is published |

We keep you updated while we work on it, and agree a disclosure date with you. Confirmed issues get a GitHub Security Advisory and, where applicable, a CVE. You are credited in the advisory and the `CHANGELOG.md` **Security** section unless you ask not to be.

Please give us a reasonable chance to release a fix before you disclose anything publicly.

## Supported versions

During the 0.x series only the latest minor release receives security fixes.

| Version | Supported |
| --- | --- |
| 0.1.x (latest) | ✅ |
| < 0.1 | ❌ |

When 1.0 ships, this policy will cover the latest major version and the previous one for at least six months.

## Scope

**In scope:** anything that lets a response pass verification when it should fail, or that lets untrusted input harm the server. This includes:

- origin, top origin and cross-origin checks
- challenge generation, comparison and single-use enforcement
- RP ID hash, user presence (UP), user verification (UV) and backup flag (BE/BS) checks
- signature verification, the algorithm allowlist, key-size minimums and COSE key consistency
- signature counter regression detection
- attestation statement verification and X.509 chain validation for every built-in [WebAuthn attestation format](https://w3c.github.io/webauthn/#sctn-defined-attestation-formats) (`none`, `packed`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `apple`)
- the CBOR, DER/ASN.1, authenticatorData and clientDataJSON parsers, including memory or CPU exhaustion from crafted input
- error messages or `toJSON()` output that leak challenges, keys, signatures or user handles
- the Android bridge's origin derivation (`androidOriginFromFingerprint`) and `buildAssetLinks`
- a runtime dependency appearing in the published package, or a compromised build or release workflow

**Out of scope:**

- certificate revocation (CRL/OCSP) and FIDO Metadata Service status checks, which are documented non-goals. Add them through `attestationVerifiers`.
- configurations the config validator explicitly allows, such as `counterPolicy: 'lenient'`, `allowCrossOrigin: true` or trust anchors you added yourself
- a statement reported as `trusted: false` being accepted by an application that decided on `type` instead of `trusted`
- vulnerabilities in your own challenge store, session handling or credential storage
- issues in browsers, authenticators or platform credential managers. Report those to their vendors.

## Security design

The checks below are on by default. New options may add strictness or an explicit opt-in. They never silently weaken a default.

- Exact origin matching, with no prefix, suffix or wildcard rules. `http:` is allowed only for `localhost`.
- Challenges come from a CSPRNG, are compared in constant time, and are deleted when they are taken.
- UP is always required. UV is required when the policy asks for it, and BE/BS must be consistent.
- An algorithm allowlist that never includes RS1, RSA keys of at least 2048 bits, and consistent COSE `kty`/`alg`/`crv` values.
- Strict parsers: bounds-checked, with no trailing bytes, no indefinite lengths, no duplicate keys, and depth and item limits.
- One error type, `WebAuthnError`, whose messages never contain secret material.
- Zero runtime dependencies. CI fails the build if a bare import appears in `dist/`.

## Using the library safely

- Serve your site over HTTPS and list every origin you accept explicitly.
- Store challenges server-side in a store with a short TTL and atomic `take`. In production, use Redis or a database instead of `MemoryChallengeStore`.
- Decide on attestation `trusted`, never on `type`. Add only the trust anchors you need.
- Keep `counterPolicy: 'strict'` unless you have a reason to change it, and treat `counterWarning` as a signal of a possibly cloned authenticator.
- Keep the package up to date, and watch this repository's security advisories.

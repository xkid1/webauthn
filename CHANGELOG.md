# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-21

First public release.

### Added

- `@xkid1/webauthn/server` provides `createWebAuthnServer`, options generation, and registration (§7.1) and authentication (§7.2) verification. It also includes `MemoryChallengeStore` and config validation with secure defaults.
- `@xkid1/webauthn/client` provides `startRegistration` and `startAuthentication`, including conditional mediation and auto-register. It adds `createWebAuthnClient`, feature detection, `getClientCapabilities`, the Signal API, and ceremony abort management.
- `@xkid1/webauthn/android` provides `createAndroidPasskeyClient` for Credential Manager bridges, plus `androidOriginFromFingerprint` and `buildAssetLinks`.
- Built-in verifiers for every WebAuthn L3 attestation format:
  - `none`, `packed` and `fido-u2f`
  - `tpm` (§8.3): TPM 2.0 `pubArea` / `certInfo` parsing and AIK certificate profile checks
  - `android-key` (§8.4): KeyDescription extension checks
  - `android-safetynet` (§8.5): JWS verification, nonce and freshness checks
  - `apple` (§8.8): anonymous attestation nonce and key binding
- `createAndroidKeyVerifier({ requireTeeEnforced })` and `createAndroidSafetyNetVerifier({ maxAgeMs, clockSkewMs })` for stricter, opt-in policies.
- Developer-friendly errors:
  - `WebAuthnError` has a `hint` with how to fix each code, and accepts an optional custom `hint`.
  - `toJSON()` returns `{ name, code, message, hint }` and is safe for APIs and logs; it leaves out `cause` and the stack.
  - `toString()` includes the code and hint.
  - `isWebAuthnError(error, ...codes)` can narrow to specific codes.
  - `getErrorHint`, `ERROR_HINTS` and the `WebAuthnErrorJSON` type.
- Every public type is exported from every entry point (type-only; no bundle-size cost).
- Zero-dependency internals:
  - a strict CBOR codec
  - a COSE key parser (EdDSA, Ed25519, ES256/384/512, RS256/384/512, PS256/384/512)
  - an ECDSA DER codec
  - an ASN.1/X.509 parser with chain validation
- Pure ESM with fully specified `.js` imports in `dist/`, so it works under `moduleResolution: nodenext`, `node16` and `bundler`.
- Project documentation: `Contributing.md`, `SECURITY.md`, `ACCESSIBILITY.md` and `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).

### Security

- RSA keys must be at least 2048 bits, for both credential keys and attestation certificates (`INVALID_PUBLIC_KEY`).
- `android-key` requires `KM_ORIGIN_GENERATED` and `KM_PURPOSE_SIGN` in both authorization lists, and rejects a KeyDescription with extra fields.
- TPM RSA `pubArea.keyBits` must match the modulus length.
- The DER reader accepts high-tag-number form only when a caller opts in (the Android KeyDescription needs it). X.509 parsing always rejects it.

[Unreleased]: https://github.com/xkid1/webauthn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xkid1/webauthn/releases/tag/v0.1.0

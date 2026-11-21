# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Built-in verifiers for the remaining WebAuthn L3 attestation formats:
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
  - New exports: `getErrorHint`, `ERROR_HINTS` and the `WebAuthnErrorJSON` type.
- The DER reader accepts high-tag-number form, but only when a caller opts in (the Android KeyDescription needs it). X.509 parsing still rejects it.
- Project documentation:
  - `Contributing.md` covers setup, commands, the non-negotiable rules, testing and the PR process.
  - `SECURITY.md` adds response targets, a supported-versions table, an expanded scope and safe-usage guidance.
  - `ACCESSIBILITY.md` explains how to build accessible passkey flows on top of the library.
  - `CODE_OF_CONDUCT.md` adopts the Contributor Covenant 2.1.

### Security

- RSA keys in attestation certificates must now be at least 2048 bits (`INVALID_PUBLIC_KEY`), the same minimum as credential keys.
- `android-key` now rejects an origin other than `KM_ORIGIN_GENERATED`, or a purpose other than `KM_PURPOSE_SIGN`, in either authorization list. Before, an origin or purpose in one list could cover a conflicting value in the other. It also rejects a KeyDescription with extra fields.
- TPM RSA `pubArea.keyBits` must match the modulus length.

### Fixed

- ECDSA certificate chain links now take the curve size from the issuer key, not from the signature OID's hash. A P-256 CA that signs with `ecdsa-with-SHA384` now verifies.
- The published `dist/types/index.d.ts` imported `./logger/logger` without a `.js` extension, which broke TypeScript users on `NodeNext`/`Node16` resolution. Every type barrel now uses explicit `.js` specifiers.
- `yarn build` failed while generating declarations (`Cannot find name 'console'` in the internal logger), so the alias rewrite never ran and the packed `dist/` still contained `@types`/`@utils` imports. The logger now reads `console` through `globalThis` with the new `ConsoleLike` / `ConsoleGlobal` types, like the other runtime globals.

### Changed

- `src/types` is organised one folder per domain, and every type that was declared inline elsewhere now lives there:
  - New domains: `asn1`, `attestation`, `browser`, `cbor`, `client-data`, `cose`, `crypto`.
  - Object types that were written inline in signatures are now named, for example `VerifyWithKeyOptions`, `CertificateChainOptions`, `CeremonyHandle`, `CborDecodeResult`, `RsaPublicKey`, `CoseWebCryptoParams` and `WebAuthnErrorOptions`.
  - All of them are exported as types from every entry point. This is type-only and does not change bundle size.
- The `libs` barrels no longer re-export types. Import types from the package entry points instead.
- `fmt` values `tpm`, `android-key`, `android-safetynet` and `apple` no longer raise `ATTESTATION_FORMAT_UNSUPPORTED`. They are verified, and are rejected with `ATTESTATION_INVALID` when malformed.

## [0.1.0] - 2026-11-21

### Added

- `@xkid1/webauthn/server` provides `createWebAuthnServer`, options generation, and registration (§7.1) and authentication (§7.2) verification. It also includes `MemoryChallengeStore` and config validation with secure defaults.
- `@xkid1/webauthn/client` provides `startRegistration` and `startAuthentication`, including conditional mediation and auto-register. It adds `createWebAuthnClient`, feature detection, `getClientCapabilities`, the Signal API, and ceremony abort management.
- `@xkid1/webauthn/android` provides `createAndroidPasskeyClient` for Credential Manager bridges, plus `androidOriginFromFingerprint` and `buildAssetLinks`.
- Zero-dependency internals:
  - a strict CBOR codec
  - a COSE key parser (EdDSA, Ed25519, ES256/384/512, RS256/384/512, PS256/384/512)
  - an ECDSA DER codec
  - an ASN.1/X.509 parser with chain validation
  - attestation formats `none`, `packed` and `fido-u2f`

[Unreleased]: https://github.com/xkid1/webauthn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xkid1/webauthn/releases/tag/v0.1.0

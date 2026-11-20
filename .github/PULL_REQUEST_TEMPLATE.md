# Pull Request

<!--
Thanks for contributing! Please read Contributing.md first.
The PR title must follow Conventional Commits, e.g. `fix(server): reject a BE=0, BS=1 response`.
Security vulnerabilities go in a private advisory (SECURITY.md), not a public PR.
-->

## Summary

<!-- What changed and why. Link the issue it fixes, e.g. "Fixes #123", and the spec step, e.g. "WebAuthn L3 §7.2 step 21". -->

## Change type

- [ ] Bug fix
- [ ] Feature or behavior change
- [ ] Security hardening (stricter check or new opt-in)
- [ ] Breaking change (removed/renamed export, changed `WebAuthnErrorCode`, or a stricter default that can reject previously accepted responses)
- [ ] Refactor or maintenance
- [ ] Documentation

## Verification

CI runs typecheck, lint, format, tests with coverage, `build` + `verify:dist`, the size
budgets and `yarn e2e` (the packed package installed offline in a fresh project, on Node
20–26). All must pass.

- [ ] `yarn check` passes locally
- [ ] `yarn e2e` passes locally (for packaging, entry-point or public API changes)
- [ ] Tests added or updated for every behavior change, using the software authenticator in `testing/`
- [ ] Every new security check has a negative test asserting the right `WebAuthnErrorCode`

## Review checklist

- [ ] No runtime dependency added (`dependencies` / `peerDependencies` stay empty)
- [ ] Runtime-agnostic: no `node:*`, `Buffer`, `atob`/`btoa`, `TextEncoder`/`TextDecoder` or DOM lib types in `src/`
- [ ] No security default weakened (exact origins, `timingSafeEqual`, single-use challenges, UP/UV, BE/BS, algorithm allowlist, counter regression, strict parsers)
- [ ] Errors are `WebAuthnError` with a hint in `hints.ts`; messages contain no challenges, keys, signatures or user handles
- [ ] Layering respected (`apps → libs → utils → types`); new types live in `src/types`
- [ ] Public API changes update `src/types`, the `index.ts` barrels, `README.md` and `e2e/consumer/`
- [ ] `CHANGELOG.md` has an entry under **Unreleased**
- [ ] Bundle-size budget changes (`bench/size-budget.json`) are explained

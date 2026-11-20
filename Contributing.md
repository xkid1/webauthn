# Contributing to @xkid1/webauthn

Thanks for your interest in improving `@xkid1/webauthn`. This guide covers how to set up the project, the rules every change has to follow, and how to get a pull request merged.

By taking part you agree to follow the [Code of Conduct](./CODE_OF_CONDUCT.md).

> **Found a vulnerability?** Don't open an issue or PR. Report it privately as described in [SECURITY.md](./SECURITY.md).

## Ways to contribute

- **Report a bug** with the [bug report form](https://github.com/xkid1/webauthn/issues/new/choose). A minimal reproduction helps most.
- **Propose a feature** with the feature request form. For larger changes, such as a new entry point, a new ceremony option or a new attestation format, open an issue first so we can agree on the design before you write code.
- **Improve the docs.** README fixes, framework recipes and clearer error hints are always welcome.
- **Add tests**, especially negative tests that prove tampered input is rejected.

## Development setup

You need:

- **Node.js 24** (see `.nvmrc`). The published package supports Node 20 and later.
- **Yarn 4**, through Corepack: `corepack enable`.

```bash
git clone https://github.com/xkid1/webauthn.git
cd webauthn
yarn install
yarn check     # typecheck + lint + format:check + test
```

### Commands

| Command | What it does |
| --- | --- |
| `yarn typecheck` | `tsc --noEmit` over `src`, `tests`, `bench` and `scripts` |
| `yarn lint` / `yarn lint:fix` | ESLint (type-aware, security and import rules) |
| `yarn format` / `yarn format:check` | Prettier |
| `yarn test` / `yarn test:watch` | Vitest |
| `yarn test:coverage` | Coverage. Thresholds: 85% lines, functions and statements, 75% branches |
| `yarn build` | clean → SWC (JS) → `tsc` (`.d.ts`) → alias rewrite |
| `yarn verify:dist` | Checks there are zero dependencies and no leftover aliases, and that every entry point loads |
| `yarn e2e` | Builds, packs and installs the package offline into a fresh app, then runs its tests |
| `yarn bench`, `yarn bench:size`, `yarn bench:runtimes` | Benchmarks, bundle-size budgets, cross-runtime timings |
| `yarn check` | Everything CI gates on except build and e2e. **Run it before every commit.** |

Run one test file with `yarn vitest run src/apps/server-side/registration`, or one test with `-t "name"`.

## Project layout

```text
src/
├── apps/    public entry points: client-side, server-side, android
├── libs/    protocol building blocks: cbor, asn1, cose, crypto, authenticator-data, client-data, attestation
├── utils/   pure helpers: base64url, bytes, utf8, guards, WebAuthnError
└── types/   every type, one folder per domain (type-only, no runtime code)
tests/       shared test support (@tests alias), never published
e2e/         tests for the packed package, used the way an application would use it
bench/       benchmarks and size budgets
scripts/     build and verification scripts
```

Dependencies only point downwards: `apps → libs → utils → types`. `import-x/no-cycle` enforces this.

## Rules every change must follow

These are non-negotiable. CI and review enforce them.

1. **Zero runtime dependencies.** Never add `dependencies` or `peerDependencies`. Dev dependencies need a good reason.
2. **Runtime-agnostic code.** Don't use `node:*`, `Buffer`, `atob`/`btoa`, `TextEncoder`/`TextDecoder` or DOM lib types in `src/`. Read globals through `globalThis` with structural types.
3. **Never weaken a security default.** Exact origins, constant-time comparisons, single-use challenges, UP/UV and BE/BS checks, the algorithm allowlist, RSA ≥ 2048 bits, counter regression detection and strict parsers all stay. New options may add strictness or an explicit opt-in.
4. **One error type.** Throw `WebAuthnError` with a `WebAuthnErrorCode`. Every code needs a hint in `src/utils/helpers/error/hints.ts`. Messages must never include challenges, keys, signatures or user handles.
5. **Types live in `src/types`.** Don't declare `interface`, `type` or inline object types anywhere else.
6. **Imports:** use the barrel aliases (`@apps`, `@libs`, `@utils`, `@types`) across layers, and relative `.js` imports inside a layer. Use `import type` for types.
7. **Cite the spec.** Verification logic carries a comment naming the step, e.g. `// §7.2 step 21`.

## Tests

- Put tests next to the module they test as `<name>.test.ts`.
- Use the **software authenticator** in `tests/authenticator.ts` to produce real, signed responses instead of hard-coded fixtures. `tests/der.ts` and `tests/attestation-formats.ts` build certificates and attestation statements with `tamper` switches.
- **Every new security check needs a negative test** that tampers with the input and asserts the exact `WebAuthnErrorCode`.
- Client tests stub globals with `vi.stubGlobal` and always restore them with `vi.unstubAllGlobals()`.
- If you change the public API, add or update a consumer test in `e2e/consumer/`. It may only import `@xkid1/webauthn[/client|/server|/android]`.

## Public API changes

A change to anything exported from `.`, `./client`, `./server` or `./android` must also update:

- `src/types` and the relevant `index.ts` barrels
- `README.md`
- `CHANGELOG.md`
- `e2e/consumer/`

Removing or renaming an export, changing a `WebAuthnErrorCode`, or tightening a default so that previously accepted responses are rejected is a **breaking change**. Call it out in the PR.

## Commits and pull requests

1. Fork the repository and create a branch from `main`.
2. Make your change with tests, then run `yarn check`. Also run `yarn e2e` if you touched packaging, entry points or the public API.
3. Add an entry under **Unreleased** in [CHANGELOG.md](./CHANGELOG.md), using the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) sections (Added, Changed, Fixed, Security, …).
4. Open a pull request and fill in the template checklist.

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/). Allowed types are `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore` and `revert`. Common scopes are `client`, `server`, `android`, `cbor`, `cose`, `attestation`, `crypto`, `types` and `deps`. For example:

```text
fix(server): reject a BE=0, BS=1 response
feat(attestation): verify the apple nonce extension
```

The title becomes the release-note entry, so describe the change from a user's point of view.

CI runs typecheck, lint, format, tests with coverage, build with `verify:dist`, size budgets, e2e on Node 20–26, and CodeQL. Everything must pass before review. If you raise a budget in `bench/size-budget.json` on purpose, explain why in the PR.

## Releases

Maintainers handle releases: bump `version` in `package.json`, move the **Unreleased** changelog entries under the new version, and push a `vX.Y.Z` tag. The release workflow verifies the build and publishes to npm (with provenance) and GitHub Packages. See [`.github/CI_BUILD_STRATEGY.md`](./.github/CI_BUILD_STRATEGY.md) for the full release pipeline.

## License

By contributing you agree that your contributions are licensed under the [MIT License](./LICENSE).

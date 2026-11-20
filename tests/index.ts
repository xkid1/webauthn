/**
 * Test support shared by colocated `*.test.ts` files and benchmarks.
 * Lives outside `src/`, so it is never compiled into `dist/` or published.
 * Import it via the `@testing` alias.
 */
export * from './attestation-formats.js';
export * from './authenticator.js';
export * from './der.js';
export * from './attestation.js';
export * from './server.js';
export * from './browser.js';

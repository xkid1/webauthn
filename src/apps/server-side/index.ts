/**
 * @module @xkid1/webauthn/server
 * Relying-party side: options generation and ceremony verification.
 * Runs anywhere WebCrypto exists (Node ≥ 20, Deno, Bun, Cloudflare Workers, Electron main).
 */
export { createAndroidKeyVerifier, createAndroidSafetyNetVerifier } from '@libs';
export {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from './authentication/index.js';
export { MemoryChallengeStore } from './challenge-store/index.js';
export { resolveConfig } from './config/index.js';
export {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from './registration/index.js';
export { createWebAuthnServer } from './server/index.js';
export type * from '@types';
export {
  ERROR_HINTS,
  fromBase64Url,
  getErrorHint,
  isWebAuthnError,
  toBase64Url,
  WebAuthnError,
} from '@utils';

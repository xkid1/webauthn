/**
 * @module @xkid1/webauthn/server
 * Relying-party side: options generation and ceremony verification.
 * Runs anywhere WebCrypto exists (Node ≥ 20, Deno, Bun, Cloudflare Workers, Electron main).
 */
export { createAndroidKeyVerifier, createAndroidSafetyNetVerifier } from '@libs';
export {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from './authentication';
export { MemoryChallengeStore } from './challenge-store';
export { resolveConfig } from './config';
export { generateRegistrationOptions, verifyRegistrationResponse } from './registration';
export { createWebAuthnServer } from './server';
export type * from '@types';
export {
  ERROR_HINTS,
  fromBase64Url,
  getErrorHint,
  isWebAuthnError,
  toBase64Url,
  WebAuthnError,
} from '@utils';

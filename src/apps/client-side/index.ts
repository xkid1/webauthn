/**
 * @module @xkid1/webauthn/client
 * Browser / Electron renderer / WebView side. Framework-agnostic and SSR-safe:
 * importing never touches `window`; functions check for the API when called.
 */
export { startAuthentication } from './authentication/index.js';
export { cancelCeremony, toCeremonyError } from './ceremony/index.js';
export { createWebAuthnClient, DEFAULT_ENDPOINTS } from './client/index.js';
export { startRegistration } from './registration/index.js';
export {
  authenticationToJSON,
  registrationToJSON,
  toCreationOptions,
  toRequestOptions,
} from './serialize/index.js';
export {
  getClientCapabilities,
  isConditionalMediationAvailable,
  isPlatformAuthenticatorAvailable,
  isWebAuthnSupported,
  signals,
} from './support/index.js';
export type * from '@types';
export {
  ERROR_HINTS,
  fromBase64Url,
  getErrorHint,
  isWebAuthnError,
  toBase64Url,
  WebAuthnError,
} from '@utils';

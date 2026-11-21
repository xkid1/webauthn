/**
 * @module @xkid1/webauthn/client
 * Browser / Electron renderer / WebView side. Framework-agnostic and SSR-safe:
 * importing never touches `window`; functions check for the API when called.
 */
export { startAuthentication } from './authentication';
export { cancelCeremony, toCeremonyError } from './ceremony';
export { createWebAuthnClient, DEFAULT_ENDPOINTS } from './client';
export { startRegistration } from './registration';
export {
  authenticationToJSON,
  registrationToJSON,
  toCreationOptions,
  toRequestOptions,
} from './serialize';
export {
  getClientCapabilities,
  isConditionalMediationAvailable,
  isPlatformAuthenticatorAvailable,
  isWebAuthnSupported,
  signals,
} from './support';
export type * from '@types';
export {
  ERROR_HINTS,
  fromBase64Url,
  getErrorHint,
  isWebAuthnError,
  toBase64Url,
  WebAuthnError,
} from '@utils';

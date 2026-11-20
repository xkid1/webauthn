/**
 * @module @xkid1/webauthn/android
 * React Native / native Android helpers built on Jetpack Credential Manager.
 */
export { buildAssetLinks } from './asset-links/index.js';
export {
  androidOriginFromFingerprint,
  fingerprintFromAndroidOrigin,
  isAndroidOrigin,
} from './origin/index.js';
export {
  createAndroidPasskeyClient,
  normaliseAuthentication,
  normaliseRegistration,
  toAndroidError,
} from './passkeys/index.js';
export type * from '@types';
export {
  ERROR_HINTS,
  fromBase64Url,
  getErrorHint,
  isWebAuthnError,
  toBase64Url,
  WebAuthnError,
} from '@utils';

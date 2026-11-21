/**
 * @module @xkid1/webauthn/android
 * React Native / native Android helpers built on Jetpack Credential Manager.
 */
export { buildAssetLinks } from './asset-links';
export {
  androidOriginFromFingerprint,
  fingerprintFromAndroidOrigin,
  isAndroidOrigin,
} from './origin';
export {
  createAndroidPasskeyClient,
  normaliseAuthentication,
  normaliseRegistration,
  toAndroidError,
} from './passkeys';
export type * from '@types';
export {
  ERROR_HINTS,
  fromBase64Url,
  getErrorHint,
  isWebAuthnError,
  toBase64Url,
  WebAuthnError,
} from '@utils';

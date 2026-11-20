/**
 * @xkid1/webauthn – zero-dependency WebAuthn / passkeys for every runtime.
 *
 * Prefer the focused entry points for the smallest bundles:
 *   import { startRegistration } from '@xkid1/webauthn/client';
 *   import { createWebAuthnServer } from '@xkid1/webauthn/server';
 *   import { createAndroidPasskeyClient } from '@xkid1/webauthn/android';
 *
 * The root entry re-exports everything (tree-shakeable; `sideEffects: false`).
 */
export * from '@apps';
export {
  COSEAlgorithm,
  decodeCbor,
  encodeCbor,
  parseAttestationObject,
  parseAuthenticatorData,
  parseClientDataJSON,
  parseCoseKey,
} from '@libs';

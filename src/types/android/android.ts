import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '../webauthn';

/**
 * Contract a React Native native module (Kotlin, using androidx.credentials
 * Credential Manager) must fulfil. Both methods receive the exact WebAuthn JSON
 * that Credential Manager's `CreatePublicKeyCredentialRequest(requestJson)` /
 * `GetPublicKeyCredentialOption(requestJson)` expect, and resolve with the
 * `registrationResponseJson` / `authenticationResponseJson` string.
 */
export interface AndroidCredentialBridge {
  createCredential(requestJson: string): Promise<string | object>;
  getCredential(requestJson: string): Promise<string | object>;
  /** Optional: report whether Credential Manager / passkeys are available (API 28+). */
  isAvailable?(): Promise<boolean>;
}

export interface AssetLinksInput {
  /** Android applicationId, e.g. "com.example.app". */
  readonly packageName: string;
  /** SHA-256 signing-certificate fingerprints ("AB:CD:…" hex, colon-separated). */
  readonly sha256CertFingerprints: readonly string[];
  /** Also grant `get_login_creds` (password + passkey sharing). Default true. */
  readonly includeLoginCredentials?: boolean;
}

export interface AssetLinkStatement {
  readonly relation: readonly string[];
  readonly target: {
    readonly namespace: 'android_app';
    readonly package_name: string;
    readonly sha256_cert_fingerprints: readonly string[];
  };
}

/**
 * Passkey client for an Android Credential Manager bridge (`createAndroidPasskeyClient`).
 * The bridge is any native module; this layer handles JSON normalisation,
 * validation and error mapping so the output is byte-for-byte what
 * `@xkid1/webauthn/server` expects.
 */
export interface AndroidPasskeyClient {
  isAvailable(): Promise<boolean>;
  startRegistration(options: {
    optionsJSON: PublicKeyCredentialCreationOptionsJSON;
  }): Promise<RegistrationResponseJSON>;
  startAuthentication(options: {
    optionsJSON: PublicKeyCredentialRequestOptionsJSON;
  }): Promise<AuthenticationResponseJSON>;
}

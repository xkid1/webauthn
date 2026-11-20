/**
 * WebAuthn Level 3 JSON shapes (W3C "PublicKeyCredential*JSON" dictionaries).
 * These are the objects that travel between server, browser and native apps.
 */

/** RFC 4648 §5 base64url string without padding. */
export type Base64URLString = string;

/** IANA COSE algorithm identifier (e.g. -7 = ES256, -8 = EdDSA, -257 = RS256). */
export type COSEAlgorithmIdentifier = number;

export type AuthenticatorTransport =
  'ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb';

export type AuthenticatorAttachment = 'platform' | 'cross-platform';
export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';
export type ResidentKeyRequirement = 'required' | 'preferred' | 'discouraged';
export type AttestationConveyancePreference =
  'none' | 'indirect' | 'direct' | 'enterprise';
export type PublicKeyCredentialHint = 'security-key' | 'client-device' | 'hybrid';
export type PublicKeyCredentialType = 'public-key';

export interface PublicKeyCredentialRpEntity {
  readonly id?: string;
  readonly name: string;
}

export interface PublicKeyCredentialUserEntityJSON {
  readonly id: Base64URLString;
  readonly name: string;
  readonly displayName: string;
}

export interface PublicKeyCredentialParameters {
  readonly type: PublicKeyCredentialType;
  readonly alg: COSEAlgorithmIdentifier;
}

export interface PublicKeyCredentialDescriptorJSON {
  readonly type: PublicKeyCredentialType;
  readonly id: Base64URLString;
  readonly transports?: readonly AuthenticatorTransport[];
}

export interface AuthenticatorSelectionCriteria {
  readonly authenticatorAttachment?: AuthenticatorAttachment;
  readonly residentKey?: ResidentKeyRequirement;
  readonly requireResidentKey?: boolean;
  readonly userVerification?: UserVerificationRequirement;
}

export interface AuthenticationExtensionsClientInputs {
  readonly credProps?: boolean;
  readonly [extension: string]: unknown;
}

export interface CredentialPropertiesOutput {
  readonly rk?: boolean;
}

export interface AuthenticationExtensionsClientOutputs {
  readonly credProps?: CredentialPropertiesOutput;
  readonly [extension: string]: unknown;
}

export interface PublicKeyCredentialCreationOptionsJSON {
  readonly rp: PublicKeyCredentialRpEntity;
  readonly user: PublicKeyCredentialUserEntityJSON;
  readonly challenge: Base64URLString;
  readonly pubKeyCredParams: readonly PublicKeyCredentialParameters[];
  readonly timeout?: number;
  readonly excludeCredentials?: readonly PublicKeyCredentialDescriptorJSON[];
  readonly authenticatorSelection?: AuthenticatorSelectionCriteria;
  readonly hints?: readonly PublicKeyCredentialHint[];
  readonly attestation?: AttestationConveyancePreference;
  readonly attestationFormats?: readonly string[];
  readonly extensions?: AuthenticationExtensionsClientInputs;
}

export interface PublicKeyCredentialRequestOptionsJSON {
  readonly challenge: Base64URLString;
  readonly timeout?: number;
  readonly rpId?: string;
  readonly allowCredentials?: readonly PublicKeyCredentialDescriptorJSON[];
  readonly userVerification?: UserVerificationRequirement;
  readonly hints?: readonly PublicKeyCredentialHint[];
  readonly extensions?: AuthenticationExtensionsClientInputs;
}

export interface AuthenticatorAttestationResponseJSON {
  readonly clientDataJSON: Base64URLString;
  readonly attestationObject: Base64URLString;
  readonly authenticatorData?: Base64URLString;
  readonly transports?: readonly AuthenticatorTransport[];
  readonly publicKeyAlgorithm?: COSEAlgorithmIdentifier;
  readonly publicKey?: Base64URLString;
}

export interface AuthenticatorAssertionResponseJSON {
  readonly clientDataJSON: Base64URLString;
  readonly authenticatorData: Base64URLString;
  readonly signature: Base64URLString;
  readonly userHandle?: Base64URLString;
}

export interface RegistrationResponseJSON {
  readonly id: Base64URLString;
  readonly rawId: Base64URLString;
  readonly type: PublicKeyCredentialType;
  readonly response: AuthenticatorAttestationResponseJSON;
  readonly authenticatorAttachment?: AuthenticatorAttachment;
  readonly clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

export interface AuthenticationResponseJSON {
  readonly id: Base64URLString;
  readonly rawId: Base64URLString;
  readonly type: PublicKeyCredentialType;
  readonly response: AuthenticatorAssertionResponseJSON;
  readonly authenticatorAttachment?: AuthenticatorAttachment;
  readonly clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

/** Decoded `clientDataJSON` (WebAuthn §5.8.1 CollectedClientData). */
export interface CollectedClientData {
  readonly type: 'webauthn.create' | 'webauthn.get';
  readonly challenge: Base64URLString;
  readonly origin: string;
  readonly crossOrigin?: boolean;
  readonly topOrigin?: string;
}

/** The optional `authenticatorAttachment` member, added only when the value is valid. */
export interface AuthenticatorAttachmentField {
  authenticatorAttachment?: AuthenticatorAttachment;
}

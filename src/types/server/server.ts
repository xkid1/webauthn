import type { CborMap } from '../cbor';
import type { CryptoLike } from '../runtime';
import type {
  AttestationConveyancePreference,
  AuthenticationExtensionsClientInputs,
  AuthenticationResponseJSON,
  AuthenticatorAttachment,
  AuthenticatorSelectionCriteria,
  AuthenticatorTransport,
  Base64URLString,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialHint,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  UserVerificationRequirement,
} from '../webauthn';

// ---------------------------------------------------------------------------
// Parsed authenticator structures
// ---------------------------------------------------------------------------

export interface AuthenticatorFlags {
  /** UP – user presence (bit 0). */
  readonly userPresent: boolean;
  /** UV – user verification (bit 2). */
  readonly userVerified: boolean;
  /** BE – backup eligibility (bit 3). */
  readonly backupEligible: boolean;
  /** BS – backup state (bit 4). */
  readonly backedUp: boolean;
  /** AT – attested credential data included (bit 6). */
  readonly attestedCredentialData: boolean;
  /** ED – extension data included (bit 7). */
  readonly extensionData: boolean;
  /** Raw flags byte. */
  readonly raw: number;
}

export interface AttestedCredentialData {
  /** 16-byte AAGUID of the authenticator model. */
  readonly aaguid: Uint8Array;
  readonly credentialId: Uint8Array;
  /** Raw COSE_Key bytes exactly as sent by the authenticator. */
  readonly credentialPublicKey: Uint8Array;
}

export interface ParsedAuthenticatorData {
  readonly rpIdHash: Uint8Array;
  readonly flags: AuthenticatorFlags;
  readonly signCount: number;
  readonly attestedCredentialData?: AttestedCredentialData;
  readonly extensions?: CborMap;
}

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

/** WebAuthn §6.5.4 attestation types. */
export type AttestationType = 'none' | 'self' | 'basic' | 'attca' | 'anonca';

export interface AttestationContext {
  readonly format: string;
  readonly attStmt: CborMap;
  readonly authData: Uint8Array;
  readonly parsedAuthData: ParsedAuthenticatorData;
  readonly clientDataHash: Uint8Array;
  readonly crypto: CryptoLike;
  /** DER-encoded trusted root certificates configured on the relying party. */
  readonly trustAnchors: readonly Uint8Array[];
  /** Current time in milliseconds (injectable for tests). */
  readonly now: number;
}

export interface AttestationResult {
  readonly type: AttestationType;
  /** DER certificates from attStmt.x5c (leaf first). Empty for none/self. */
  readonly trustPath: readonly Uint8Array[];
  /** `true` only when the chain was verified up to a configured trust anchor. */
  readonly trusted: boolean;
}

/** Plug-in verifier for an attestation statement format (e.g. a vendor-specific fmt). */
export type AttestationVerifier = (
  context: AttestationContext,
) => Promise<AttestationResult>;

/** Options for `createAndroidKeyVerifier`. */
export interface AndroidKeyVerifierOptions {
  /**
   * Accept only keys whose origin and purpose are enforced by the TEE / StrongBox
   * (`teeEnforced`). Default `false`, which uses the union with `softwareEnforced`
   * as WebAuthn §8.4.1 specifies.
   */
  readonly requireTeeEnforced?: boolean;
}

/** Options for `createAndroidSafetyNetVerifier`. */
export interface AndroidSafetyNetVerifierOptions {
  /** Maximum age of the SafetyNet response `timestampMs`. Default 60 000 ms. */
  readonly maxAgeMs?: number;
  /** Tolerance for a `timestampMs` ahead of the server clock. Default 0. */
  readonly clockSkewMs?: number;
}

// ---------------------------------------------------------------------------
// Relying party configuration
// ---------------------------------------------------------------------------

export type CounterPolicy = 'strict' | 'lenient';

export interface RelyingPartyConfig {
  /** Effective domain, e.g. "example.com". Never include scheme or port. */
  readonly rpId: string;
  /** Human-readable name shown by some authenticators. */
  readonly rpName: string;
  /**
   * Exact origin allowlist, e.g. ["https://example.com", "android:apk-key-hash:..."].
   * Compared byte-for-byte; no wildcards.
   */
  readonly origins: readonly string[];
  /** Ceremony timeout in ms. Default 300 000 (5 min). Also the challenge TTL. */
  readonly timeout?: number;
  /** Requested UV. Default "preferred". */
  readonly userVerification?: UserVerificationRequirement;
  /** Enforce the UV flag server-side. Default: `userVerification === "required"`. */
  readonly requireUserVerification?: boolean;
  /** Default "none" (privacy-preserving, recommended for most consumer sites). */
  readonly attestation?: AttestationConveyancePreference;
  /** Accepted COSE algorithms in preference order. Default [-8, -7, -257]. */
  readonly supportedAlgorithms?: readonly COSEAlgorithmIdentifier[];
  readonly authenticatorSelection?: AuthenticatorSelectionCriteria;
  readonly hints?: readonly PublicKeyCredentialHint[];
  /** Challenge length in bytes. Default 32, minimum 16. */
  readonly challengeSize?: number;
  /** Accept `crossOrigin: true` client data (iframes). Default false. */
  readonly allowCrossOrigin?: boolean;
  /** Required when `allowCrossOrigin` is true: allowlist for `topOrigin`. */
  readonly allowedTopOrigins?: readonly string[];
  /** "strict" (default) throws on a non-increasing signature counter; "lenient" reports it. */
  readonly counterPolicy?: CounterPolicy;
  /** Extra / overriding attestation statement verifiers keyed by fmt. */
  readonly attestationVerifiers?: Readonly<Record<string, AttestationVerifier>>;
  /** DER root certificates used to validate attestation chains. */
  readonly trustAnchors?: readonly Uint8Array[];
  /** Reject registrations whose attestation does not chain to `trustAnchors`. Default false. */
  readonly requireTrustedAttestation?: boolean;
  /** Inject a WebCrypto implementation. Default `globalThis.crypto`. */
  readonly crypto?: CryptoLike;
  /** Clock override (ms since epoch). */
  readonly now?: () => number;
}

/** Fully-resolved configuration with defaults applied. */
export interface ResolvedRelyingPartyConfig {
  readonly rpId: string;
  readonly rpName: string;
  readonly origins: readonly string[];
  readonly timeout: number;
  readonly userVerification: UserVerificationRequirement;
  readonly requireUserVerification: boolean;
  readonly attestation: AttestationConveyancePreference;
  readonly supportedAlgorithms: readonly COSEAlgorithmIdentifier[];
  readonly authenticatorSelection: AuthenticatorSelectionCriteria;
  readonly hints: readonly PublicKeyCredentialHint[];
  readonly challengeSize: number;
  readonly allowCrossOrigin: boolean;
  readonly allowedTopOrigins: readonly string[];
  readonly counterPolicy: CounterPolicy;
  readonly attestationVerifiers: Readonly<Record<string, AttestationVerifier>>;
  readonly trustAnchors: readonly Uint8Array[];
  readonly requireTrustedAttestation: boolean;
  readonly crypto: CryptoLike;
  readonly now: () => number;
}

// ---------------------------------------------------------------------------
// Ceremony inputs / outputs
// ---------------------------------------------------------------------------

export interface WebAuthnUserInput {
  /**
   * Opaque user handle (max 64 bytes). Must NOT contain PII such as email.
   * Omit to generate a random 32-byte handle (persist it with the user!).
   */
  readonly id?: Uint8Array | Base64URLString;
  /** Account identifier shown to the user, e.g. email or username. */
  readonly name: string;
  readonly displayName?: string;
}

/** What you persist per credential after registration. */
export interface StoredCredential {
  readonly id: Base64URLString;
  /** COSE_Key bytes (base64url or raw). */
  readonly publicKey: Base64URLString | Uint8Array;
  readonly counter: number;
  readonly transports?: readonly AuthenticatorTransport[];
}

export type CredentialDescriptorInput = Pick<StoredCredential, 'id' | 'transports'>;

export interface GenerateRegistrationOptionsInput {
  readonly user: WebAuthnUserInput;
  /** Credentials the user already has – prevents duplicate registration on one authenticator. */
  readonly excludeCredentials?: readonly CredentialDescriptorInput[];
  readonly authenticatorSelection?: AuthenticatorSelectionCriteria;
  readonly attestation?: AttestationConveyancePreference;
  readonly extensions?: AuthenticationExtensionsClientInputs;
  readonly hints?: readonly PublicKeyCredentialHint[];
  readonly timeout?: number;
  /** Supply your own challenge (min 16 bytes). Normally leave undefined. */
  readonly challenge?: Uint8Array;
}

export interface GenerateAuthenticationOptionsInput {
  /** Omit (or empty) for discoverable-credential / passkey autofill flows. */
  readonly allowCredentials?: readonly CredentialDescriptorInput[];
  readonly userVerification?: UserVerificationRequirement;
  readonly extensions?: AuthenticationExtensionsClientInputs;
  readonly hints?: readonly PublicKeyCredentialHint[];
  readonly timeout?: number;
  readonly challenge?: Uint8Array;
}

export interface VerifyRegistrationInput {
  readonly response: RegistrationResponseJSON;
  readonly expectedChallenge: Base64URLString;
  /** Override the RP-wide UV enforcement for this ceremony. */
  readonly requireUserVerification?: boolean;
}

export interface VerifyAuthenticationInput {
  readonly response: AuthenticationResponseJSON;
  readonly expectedChallenge: Base64URLString;
  /** The stored credential looked up by `response.id`. */
  readonly credential: StoredCredential;
  /** When known (non-discoverable flow or after lookup), the user handle must match. */
  readonly expectedUserHandle?: Base64URLString | Uint8Array;
  readonly requireUserVerification?: boolean;
}

export type CredentialDeviceType = 'singleDevice' | 'multiDevice';

export interface RegisteredCredential {
  readonly id: Base64URLString;
  /** COSE_Key, base64url – persist as-is. */
  readonly publicKey: Base64URLString;
  readonly algorithm: COSEAlgorithmIdentifier;
  readonly counter: number;
  readonly transports: readonly AuthenticatorTransport[];
  /** AAGUID formatted as a UUID string. */
  readonly aaguid: string;
  readonly deviceType: CredentialDeviceType;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  /** `true`/`false` when the client reported credProps.rk, otherwise undefined. */
  readonly discoverable?: boolean;
  readonly attachment?: AuthenticatorAttachment;
}

export interface VerifiedRegistration {
  readonly credential: RegisteredCredential;
  readonly userVerified: boolean;
  readonly attestation: {
    readonly format: string;
    readonly type: AttestationType;
    readonly trusted: boolean;
    readonly trustPath: readonly Uint8Array[];
  };
  readonly origin: string;
}

export interface VerifiedAuthentication {
  readonly credentialId: Base64URLString;
  /** Persist this as the credential's new counter. */
  readonly newCounter: number;
  readonly userVerified: boolean;
  readonly deviceType: CredentialDeviceType;
  readonly backupEligible: boolean;
  /** Persist: backup state may change over a credential's lifetime. */
  readonly backedUp: boolean;
  readonly userHandle?: Base64URLString;
  readonly origin: string;
  /** Only set under `counterPolicy: "lenient"` when a possible clone was detected. */
  readonly counterWarning?: boolean;
}

// ---------------------------------------------------------------------------
// Server facade
// ---------------------------------------------------------------------------

export interface WebAuthnServerConfig extends RelyingPartyConfig {
  /** Enables `sessionKey`-based challenge handling (single-use, TTL = timeout). */
  readonly challengeStore?: ChallengeStore;
}

/** Either pass the challenge you stored yourself, or let the configured store look it up. */
export type ChallengeSource =
  | { readonly expectedChallenge: Base64URLString; readonly sessionKey?: never }
  | { readonly sessionKey: string; readonly expectedChallenge?: never };

export interface WebAuthnServer {
  readonly config: ResolvedRelyingPartyConfig;
  generateRegistrationOptions(
    input: GenerateRegistrationOptionsInput & { readonly sessionKey?: string },
  ): Promise<PublicKeyCredentialCreationOptionsJSON>;
  verifyRegistration(
    input: Omit<VerifyRegistrationInput, 'expectedChallenge'> & ChallengeSource,
  ): Promise<VerifiedRegistration>;
  generateAuthenticationOptions(
    input?: GenerateAuthenticationOptionsInput & { readonly sessionKey?: string },
  ): Promise<PublicKeyCredentialRequestOptionsJSON>;
  verifyAuthentication(
    input: Omit<VerifyAuthenticationInput, 'expectedChallenge'> & ChallengeSource,
  ): Promise<VerifiedAuthentication>;
}

// ---------------------------------------------------------------------------
// Challenge storage
// ---------------------------------------------------------------------------

/**
 * Single-use challenge storage. `take` MUST delete the entry it returns so a
 * challenge can never be replayed. Back it with Redis, your session, a DB row…
 */
export interface ChallengeStore {
  set(key: string, challenge: Base64URLString, ttlMs: number): Promise<void> | void;
  take(key: string): Promise<Base64URLString | undefined> | Base64URLString | undefined;
}

/** Options for `MemoryChallengeStore`. */
export interface MemoryChallengeStoreOptions {
  /** Hard cap on outstanding challenges (oldest evicted first). Default 10 000. */
  readonly maxEntries?: number;
  /** Clock override. */
  readonly now?: () => number;
}

/** Which ceremony a stored challenge belongs to (registration and authentication are namespaced apart). */
export type CeremonyKind = 'registration' | 'authentication';

/** One pending challenge inside `MemoryChallengeStore`. */
export interface StoredChallenge {
  readonly challenge: Base64URLString;
  /** Epoch milliseconds after which the challenge is rejected. */
  readonly expiresAt: number;
}

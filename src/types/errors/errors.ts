/** Serializable form of a WebAuthnError (`error.toJSON()`): safe to log or return from an API. */
export interface WebAuthnErrorJSON {
  readonly name: 'WebAuthnError';
  readonly code: WebAuthnErrorCode;
  /** What went wrong. Never contains challenges, keys, signatures or user handles. */
  readonly message: string;
  /** How to fix or handle it. */
  readonly hint: string;
}

/** Stable, machine-readable error codes. Never parse error messages; switch on these. */
export type WebAuthnErrorCode =
  // Input / environment
  | 'INVALID_INPUT'
  | 'INVALID_CONFIG'
  | 'ENCODING_ERROR'
  | 'CBOR_ERROR'
  | 'ASN1_ERROR'
  | 'UNSUPPORTED_ENVIRONMENT'
  // Client data
  | 'TYPE_MISMATCH'
  | 'CHALLENGE_MISMATCH'
  | 'CHALLENGE_NOT_FOUND'
  | 'ORIGIN_MISMATCH'
  | 'CROSS_ORIGIN_NOT_ALLOWED'
  | 'TOP_ORIGIN_MISMATCH'
  // Authenticator data
  | 'RP_ID_MISMATCH'
  | 'USER_PRESENCE_REQUIRED'
  | 'USER_VERIFICATION_REQUIRED'
  | 'INVALID_FLAGS'
  | 'INVALID_AUTHENTICATOR_DATA'
  // Keys & signatures
  | 'UNSUPPORTED_ALGORITHM'
  | 'INVALID_PUBLIC_KEY'
  | 'SIGNATURE_INVALID'
  // Attestation
  | 'ATTESTATION_INVALID'
  | 'ATTESTATION_FORMAT_UNSUPPORTED'
  | 'ATTESTATION_UNTRUSTED'
  // Credentials
  | 'CREDENTIAL_ID_MISMATCH'
  | 'CREDENTIAL_ID_TOO_LONG'
  | 'USER_HANDLE_MISMATCH'
  | 'COUNTER_REGRESSION'
  // Client ceremonies (mapped from DOMException names)
  | 'CEREMONY_ABORTED'
  | 'CEREMONY_NOT_ALLOWED'
  | 'CREDENTIAL_EXCLUDED'
  | 'SECURITY_ERROR'
  | 'NOT_SUPPORTED'
  | 'CONSTRAINT_ERROR'
  | 'NETWORK_ERROR'
  | 'UNKNOWN_ERROR';

/** Options for the `WebAuthnError` constructor. */
export interface WebAuthnErrorOptions {
  /** The underlying error, e.g. a DOMException. Never serialised by `toJSON()`. */
  readonly cause?: unknown;
  /** Overrides the default "how to fix" hint for the code. */
  readonly hint?: string;
}

/** Narrows an error's `code` to `C` (used by `isWebAuthnError(error, ...codes)`). */
export interface WithErrorCode<C extends WebAuthnErrorCode> {
  readonly code: C;
}

import type { WebAuthnErrorCode } from '@types';

/**
 * One actionable "how to fix" per error code, written for the developer
 * integrating this package. Hints are static text: they never contain request
 * data, challenges, keys or user handles.
 *
 * Typed as a full Record so adding a code without a hint fails to compile.
 */
export const ERROR_HINTS: Readonly<Record<WebAuthnErrorCode, string>> = Object.freeze({
  // Input / environment
  INVALID_INPUT:
    'A value passed to the library has the wrong shape. Check the argument named in the message against its TypeScript type.',
  INVALID_CONFIG:
    'Fix the relying-party config passed to resolveConfig / createWebAuthnServer. rpId must be a bare domain and every origin must use https:// (http:// only for localhost).',
  ENCODING_ERROR:
    'A field is not valid base64url. Send credential responses exactly as produced by startRegistration / startAuthentication, without re-encoding them.',
  CBOR_ERROR:
    'The attestation object or COSE key is not valid CBOR. The response was probably truncated or modified in transit.',
  ASN1_ERROR:
    'An attestation certificate is malformed. Use attestation: "none" unless you need device provenance.',
  UNSUPPORTED_ENVIRONMENT:
    'WebAuthn or WebCrypto is unavailable here. In the browser, use a secure context (https or localhost); on the server, pass `crypto` (e.g. webcrypto from node:crypto).',

  // Client data
  TYPE_MISMATCH:
    'The response comes from the wrong ceremony. Send registration responses to the registration endpoint and authentication responses to the login endpoint.',
  CHALLENGE_MISMATCH:
    'The response was signed for a different challenge. Use the challenge you generated for this ceremony and do not reuse options across requests.',
  CHALLENGE_NOT_FOUND:
    'The challenge expired, was already used, or belongs to another session. Generate fresh options and retry; challenges are single-use and expire after `timeout`.',
  ORIGIN_MISMATCH:
    'The page origin is not in config.origins. Add the exact origin (scheme, host and port), e.g. "https://login.example.com" or "android:apk-key-hash:…".',
  CROSS_ORIGIN_NOT_ALLOWED:
    'The ceremony ran inside a cross-origin iframe. Set allowCrossOrigin: true and list the embedding page in allowedTopOrigins if this is intended.',
  TOP_ORIGIN_MISMATCH: 'Add the embedding page origin to config.allowedTopOrigins.',

  // Authenticator data
  RP_ID_MISMATCH:
    'The credential belongs to a different rpId. config.rpId must equal the domain used when the credential was created (or a registrable suffix of the page host).',
  USER_PRESENCE_REQUIRED:
    'The authenticator did not confirm user presence. Ask the user to retry and touch or unlock their authenticator.',
  USER_VERIFICATION_REQUIRED:
    'User verification (PIN or biometrics) is required but was not performed. Ask the user to retry, or set requireUserVerification: false if UV is optional for you.',
  INVALID_FLAGS:
    'The authenticator reported inconsistent flags (for example backed-up but not backup-eligible). Treat the response as invalid and ask the user to retry.',
  INVALID_AUTHENTICATOR_DATA:
    'authenticatorData is malformed or truncated. Forward the response unchanged from the client.',

  // Keys & signatures
  UNSUPPORTED_ALGORITHM:
    'The credential uses an algorithm that is not enabled. Allowed algorithms are set by config.supportedAlgorithms (RS1 is never accepted).',
  INVALID_PUBLIC_KEY:
    'The stored public key is invalid. Store credential.publicKey from verifyRegistrationResponse unchanged and pass it back as-is.',
  SIGNATURE_INVALID:
    'The signature did not verify. Make sure you look up the stored public key by the credential id from the response, and that the response was not modified.',

  // Attestation
  ATTESTATION_INVALID:
    'The attestation statement failed verification. Reject the registration, or request attestation: "none" if you do not need device provenance.',
  ATTESTATION_FORMAT_UNSUPPORTED:
    'No verifier is registered for this attestation format. Register one in config.attestationVerifiers or request attestation: "none".',
  ATTESTATION_UNTRUSTED:
    'The attestation chain does not end at one of config.trustAnchors. Add the vendor root certificate, or disable requireTrustedAttestation.',

  // Credentials
  CREDENTIAL_ID_MISMATCH:
    'The response credential id differs from the stored credential. Look up the credential by response.id before verifying.',
  CREDENTIAL_ID_TOO_LONG:
    'Credential ids are limited to 1023 bytes; reject this response.',
  USER_HANDLE_MISMATCH:
    'The response belongs to a different user. Verify that the credential is registered to the account that is signing in.',
  COUNTER_REGRESSION:
    'The signature counter did not increase, which can mean a cloned authenticator. Investigate the credential, or use counterPolicy: "lenient" to only report it.',

  // Client ceremonies
  CEREMONY_ABORTED:
    'The ceremony was cancelled, by the user, a timeout or a newer ceremony. Usually safe to ignore or let the user retry.',
  CEREMONY_NOT_ALLOWED:
    'The user dismissed the prompt, it timed out, or no matching credential exists on this device. Offer a retry or another sign-in method.',
  CREDENTIAL_EXCLUDED:
    'This authenticator already holds a credential for the account (excludeCredentials). Tell the user the device is already registered.',
  SECURITY_ERROR:
    'The browser rejected the request for security reasons. The page origin must match rpId (same domain or a subdomain) and use https.',
  NOT_SUPPORTED:
    'The authenticator or browser does not support the requested options. Relax authenticatorSelection or supportedAlgorithms, or check isWebAuthnSupported() first.',
  CONSTRAINT_ERROR:
    'The authenticator cannot meet a requirement, such as residentKey: "required" or userVerification: "required". Use "preferred" for wider support.',
  NETWORK_ERROR:
    'The request to your WebAuthn endpoint failed. Check the endpoint URL, CORS and credentials settings, and server availability.',
  UNKNOWN_ERROR:
    'An unexpected error occurred. Inspect `cause` for the underlying error and report it if it looks like a library bug.',
});

/** The "how to fix" hint for an error code. */
export const getErrorHint = (code: WebAuthnErrorCode): string => ERROR_HINTS[code];

import type { AbortSignalLike } from '../runtime';

/**
 * Structural views of the browser globals we use. Reading them through
 * `globalThis` (instead of DOM lib types) keeps this module importable in
 * Node, SSR (Next/Nuxt/SvelteKit/Angular Universal) and React Native, where
 * the globals simply do not exist.
 */

export type BinarySource = Uint8Array<ArrayBuffer>;

export interface CredentialDescriptorBinary {
  type: 'public-key';
  id: BinarySource;
  transports?: string[];
}

export interface CreationOptionsBinary {
  rp: { id?: string; name: string };
  user: { id: BinarySource; name: string; displayName: string };
  challenge: BinarySource;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout?: number;
  excludeCredentials?: CredentialDescriptorBinary[];
  authenticatorSelection?: Record<string, unknown>;
  hints?: string[];
  attestation?: string;
  attestationFormats?: string[];
  extensions?: Record<string, unknown>;
}

export interface RequestOptionsBinary {
  challenge: BinarySource;
  timeout?: number;
  rpId?: string;
  allowCredentials?: CredentialDescriptorBinary[];
  userVerification?: string;
  hints?: string[];
  extensions?: Record<string, unknown>;
}

export interface AuthenticatorResponseLike {
  readonly clientDataJSON: ArrayBuffer;
  readonly attestationObject?: ArrayBuffer;
  readonly authenticatorData?: ArrayBuffer;
  readonly signature?: ArrayBuffer;
  readonly userHandle?: ArrayBuffer | null;
  getTransports?(): string[];
  getPublicKeyAlgorithm?(): number;
  getPublicKey?(): ArrayBuffer | null;
  getAuthenticatorData?(): ArrayBuffer;
}

export interface PublicKeyCredentialLike {
  readonly id: string;
  readonly rawId: ArrayBuffer;
  readonly type: string;
  readonly authenticatorAttachment?: string | null;
  readonly response: AuthenticatorResponseLike;
  getClientExtensionResults(): Record<string, unknown>;
}

export interface CredentialsContainerLike {
  create(options: {
    publicKey: CreationOptionsBinary;
    signal?: AbortSignalLike;
    mediation?: string;
  }): Promise<unknown>;
  get(options: {
    publicKey: RequestOptionsBinary;
    signal?: AbortSignalLike;
    mediation?: string;
  }): Promise<unknown>;
}

export interface PublicKeyCredentialStatic {
  isUserVerifyingPlatformAuthenticatorAvailable?(): Promise<boolean>;
  isConditionalMediationAvailable?(): Promise<boolean>;
  getClientCapabilities?(): Promise<Record<string, boolean>>;
  signalUnknownCredential?(options: {
    rpId: string;
    credentialId: string;
  }): Promise<void>;
  signalAllAcceptedCredentials?(options: {
    rpId: string;
    userId: string;
    allAcceptedCredentialIds: string[];
  }): Promise<void>;
  signalCurrentUserDetails?(options: {
    rpId: string;
    userId: string;
    name: string;
    displayName: string;
  }): Promise<void>;
}

export interface AbortControllerLike {
  readonly signal: AbortSignalLike;
  abort(reason?: unknown): void;
}

/** The browser globals the client reads, all optional (SSR / React Native safe). */
export interface BrowserGlobals {
  navigator?: { credentials?: Partial<CredentialsContainerLike> };
  PublicKeyCredential?: PublicKeyCredentialStatic;
  AbortController?: new () => AbortControllerLike;
  document?: { querySelectorAll(selector: string): { length: number } };
  isSecureContext?: boolean;
}

/** An active ceremony's abort signal and its cleanup (`beginCeremony`). */
export interface CeremonyHandle {
  signal: AbortSignalLike | undefined;
  end: () => void;
}

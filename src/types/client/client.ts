import type { AbortSignalLike, FetchLike } from '../runtime';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '../webauthn';

export interface StartRegistrationOptions {
  readonly optionsJSON: PublicKeyCredentialCreationOptionsJSON;
  /** Cancel the ceremony. */
  readonly signal?: AbortSignalLike;
  /**
   * Conditional create (passkey upgrade after a password sign-in). Silent if
   * unsupported by the browser or password manager.
   */
  readonly useAutoRegister?: boolean;
}

export interface StartAuthenticationOptions {
  readonly optionsJSON: PublicKeyCredentialRequestOptionsJSON;
  readonly signal?: AbortSignalLike;
  /**
   * Conditional mediation (passkey autofill). Requires an
   * `<input autocomplete="username webauthn">` on the page.
   */
  readonly useBrowserAutofill?: boolean;
  /** When autofill is used, throw early if no `webauthn` autocomplete input exists. Default true. */
  readonly verifyBrowserAutofillInput?: boolean;
}

export interface ClientCapabilities {
  readonly webauthn: boolean;
  readonly platformAuthenticator: boolean;
  readonly conditionalGet: boolean;
  readonly conditionalCreate: boolean;
  readonly hybridTransport: boolean;
  readonly passkeyPlatformAuthenticator: boolean;
  /** Raw result of `PublicKeyCredential.getClientCapabilities()` when available. */
  readonly raw: Readonly<Record<string, boolean>>;
}

export interface WebAuthnEndpoints {
  readonly registrationOptions: string;
  readonly registrationVerify: string;
  readonly authenticationOptions: string;
  readonly authenticationVerify: string;
}

export interface WebAuthnClientConfig {
  /** Prefix for every endpoint, e.g. "https://api.example.com/auth". Default "". */
  readonly baseUrl?: string;
  readonly endpoints?: Partial<WebAuthnEndpoints>;
  /** Custom fetch (axios adapter, Angular HttpClient wrapper, test double…). */
  readonly fetch?: FetchLike;
  /** Static headers or a function evaluated per request (CSRF token, bearer…). */
  readonly headers?:
    | Readonly<Record<string, string>>
    | (() =>
        Readonly<Record<string, string>> | Promise<Readonly<Record<string, string>>>);
  /** Fetch credentials mode. Default "include" (cookie session). */
  readonly credentials?: 'include' | 'same-origin' | 'omit';
}

export interface WebAuthnClient {
  register(
    body?: Readonly<Record<string, unknown>>,
    options?: Pick<StartRegistrationOptions, 'signal' | 'useAutoRegister'>,
  ): Promise<unknown>;
  authenticate(
    body?: Readonly<Record<string, unknown>>,
    options?: Pick<StartAuthenticationOptions, 'signal' | 'useBrowserAutofill'>,
  ): Promise<unknown>;
  /** Cancel any in-flight ceremony (e.g. when a route unmounts). */
  cancel(): void;
}

/** Result of a raw ceremony, before it is sent to your server. */
export type CeremonyResponseJSON = RegistrationResponseJSON | AuthenticationResponseJSON;

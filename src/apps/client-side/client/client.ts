import { isRecord, WebAuthnError } from '@utils';

import { startAuthentication } from '../authentication';
import { cancelCeremony } from '../ceremony';
import { startRegistration } from '../registration';

import type {
  AuthenticationResponseJSON,
  FetchGlobal,
  FetchLike,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  WebAuthnClient,
  WebAuthnClientConfig,
  WebAuthnEndpoints,
} from '@types';

export const DEFAULT_ENDPOINTS: WebAuthnEndpoints = Object.freeze({
  registrationOptions: '/webauthn/register/options',
  registrationVerify: '/webauthn/register/verify',
  authenticationOptions: '/webauthn/authenticate/options',
  authenticationVerify: '/webauthn/authenticate/verify',
});

/** Unwrap `{ publicKey: … }` or `{ options: … }` envelopes some servers use. */
function unwrapOptions(value: unknown): Record<string, unknown> {
  if (isRecord(value)) {
    if (isRecord(value.publicKey)) return value.publicKey;
    if (isRecord(value.options)) return value.options;
    if (typeof value.challenge === 'string') return value;
  }
  throw new WebAuthnError('INVALID_INPUT', 'Server did not return WebAuthn options');
}

/**
 * Batteries-included browser client: fetch options → run ceremony → POST
 * result. Every part is customisable (endpoints, fetch, headers, credentials)
 * so it fits React Query, Vue composables, Angular services, SvelteKit actions
 * or a plain script.
 *
 * The verify request body is `{ ...body, response }`.
 */
export function createWebAuthnClient(config: WebAuthnClientConfig = {}): WebAuthnClient {
  const endpoints: WebAuthnEndpoints = { ...DEFAULT_ENDPOINTS, ...config.endpoints };
  const baseUrl = (config.baseUrl ?? '').replace(/\/+$/u, '');
  const fetchImpl: FetchLike | undefined =
    config.fetch ?? (globalThis as unknown as FetchGlobal).fetch?.bind(globalThis);

  async function post(path: string, body: unknown): Promise<unknown> {
    if (!fetchImpl)
      throw new WebAuthnError(
        'UNSUPPORTED_ENVIRONMENT',
        'fetch is not available; pass config.fetch',
      );
    const headers =
      typeof config.headers === 'function' ? await config.headers() : config.headers;
    let res;
    try {
      res = await fetchImpl(`${baseUrl}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...headers,
        },
        body: JSON.stringify(body ?? {}),
        credentials: config.credentials ?? 'include',
      });
    } catch (cause) {
      throw new WebAuthnError('NETWORK_ERROR', `Request to ${path} failed`, { cause });
    }
    const data: unknown = await res.json().catch(() => undefined);
    if (!res.ok) {
      const message =
        isRecord(data) && typeof data.message === 'string'
          ? data.message
          : `HTTP ${res.status}`;
      throw new WebAuthnError('NETWORK_ERROR', `${path}: ${message}`, { cause: data });
    }
    return data;
  }

  return {
    async register(body = {}, options = {}) {
      const optionsJSON = unwrapOptions(
        await post(endpoints.registrationOptions, body),
      ) as unknown as PublicKeyCredentialCreationOptionsJSON;
      const response: RegistrationResponseJSON = await startRegistration({
        optionsJSON,
        ...options,
      });
      return post(endpoints.registrationVerify, { ...body, response });
    },
    async authenticate(body = {}, options = {}) {
      const optionsJSON = unwrapOptions(
        await post(endpoints.authenticationOptions, body),
      ) as unknown as PublicKeyCredentialRequestOptionsJSON;
      const response: AuthenticationResponseJSON = await startAuthentication({
        optionsJSON,
        ...options,
      });
      return post(endpoints.authenticationVerify, { ...body, response });
    },
    cancel: cancelCeremony,
  };
}

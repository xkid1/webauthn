import { WebAuthnError } from '@utils';

import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '../authentication/index.js';
import { resolveConfig } from '../config/index.js';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from '../registration/index.js';

import type {
  Base64URLString,
  CeremonyKind,
  ChallengeSource,
  ResolvedRelyingPartyConfig,
  WebAuthnServer,
  WebAuthnServerConfig,
} from '@types';

/**
 * Create a configured relying party. Configuration is validated once, here,
 * so misconfiguration fails at boot rather than at a user's first sign-in.
 *
 * @example
 * const webauthn = createWebAuthnServer({
 *   rpId: 'example.com',
 *   rpName: 'Example',
 *   origins: ['https://example.com'],
 *   challengeStore: new MemoryChallengeStore(),
 * });
 */
export function createWebAuthnServer(options: WebAuthnServerConfig): WebAuthnServer {
  const config: ResolvedRelyingPartyConfig = resolveConfig(options);
  const store = options.challengeStore;
  const storeKey = (ceremony: CeremonyKind, sessionKey: string): string =>
    `webauthn:${ceremony}:${sessionKey}`;

  async function remember(
    ceremony: CeremonyKind,
    sessionKey: string | undefined,
    challenge: Base64URLString,
  ) {
    if (sessionKey === undefined) return;
    if (!store)
      throw new WebAuthnError(
        'INVALID_CONFIG',
        'sessionKey requires a configured challengeStore',
      );
    await store.set(storeKey(ceremony, sessionKey), challenge, config.timeout);
  }

  async function recall(
    ceremony: CeremonyKind,
    source: ChallengeSource,
  ): Promise<Base64URLString> {
    if (source.expectedChallenge !== undefined) return source.expectedChallenge;
    if (!store)
      throw new WebAuthnError(
        'INVALID_CONFIG',
        'sessionKey requires a configured challengeStore',
      );
    const challenge = await store.take(storeKey(ceremony, source.sessionKey));
    if (challenge === undefined) {
      throw new WebAuthnError(
        'CHALLENGE_NOT_FOUND',
        'No pending challenge (expired or already used)',
      );
    }
    return challenge;
  }

  return Object.freeze({
    config,

    async generateRegistrationOptions(input) {
      const { sessionKey, ...rest } = input;
      const result = generateRegistrationOptions(config, rest);
      await remember('registration', sessionKey, result.challenge);
      return result;
    },

    async verifyRegistration(input) {
      const { sessionKey: _s, expectedChallenge: _e, ...rest } = input;
      const challenge = await recall('registration', input);
      return verifyRegistrationResponse(config, {
        ...rest,
        expectedChallenge: challenge,
      });
    },

    async generateAuthenticationOptions(input = {}) {
      const { sessionKey, ...rest } = input;
      const result = generateAuthenticationOptions(config, rest);
      await remember('authentication', sessionKey, result.challenge);
      return result;
    },

    async verifyAuthentication(input) {
      const { sessionKey: _s, expectedChallenge: _e, ...rest } = input;
      const challenge = await recall('authentication', input);
      return verifyAuthenticationResponse(config, {
        ...rest,
        expectedChallenge: challenge,
      });
    },
  } satisfies WebAuthnServer);
}

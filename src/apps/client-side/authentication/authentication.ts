import { WebAuthnError } from '@utils';

import { beginCeremony, toCeremonyError } from '../ceremony/index.js';
import {
  countWebAuthnInputs,
  getCredentialsContainer,
  getPublicKeyCredential,
} from '../environment/index.js';
import { authenticationToJSON, toRequestOptions } from '../serialize/index.js';

import type { AuthenticationResponseJSON, StartAuthenticationOptions } from '@types';

/**
 * Run `navigator.credentials.get()`. With `useBrowserAutofill` this performs
 * conditional mediation (passkeys offered in the username field's autofill).
 */
export async function startAuthentication(
  options: StartAuthenticationOptions,
): Promise<AuthenticationResponseJSON> {
  const container = getCredentialsContainer();
  const publicKey = toRequestOptions(options.optionsJSON);

  if (options.useBrowserAutofill) {
    const available = await getPublicKeyCredential()
      ?.isConditionalMediationAvailable?.()
      .catch(() => false);
    if (!available) {
      throw new WebAuthnError(
        'NOT_SUPPORTED',
        'Conditional mediation (passkey autofill) is not supported',
      );
    }
    if ((options.verifyBrowserAutofillInput ?? true) && countWebAuthnInputs() === 0) {
      throw new WebAuthnError(
        'INVALID_INPUT',
        'No <input autocomplete="username webauthn"> found for passkey autofill',
      );
    }
    // Conditional UI must not restrict credentials.
    delete publicKey.allowCredentials;
  }

  const ceremony = beginCeremony(options.signal);
  try {
    const credential = await container.get({
      publicKey,
      ...(ceremony.signal ? { signal: ceremony.signal } : {}),
      ...(options.useBrowserAutofill ? { mediation: 'conditional' } : {}),
    });
    if (credential === null) {
      throw toCeremonyError({
        name: 'NotAllowedError',
        message: 'No credential returned',
      });
    }
    return authenticationToJSON(credential);
  } catch (error) {
    throw toCeremonyError(error, ceremony.signal);
  } finally {
    ceremony.end();
  }
}

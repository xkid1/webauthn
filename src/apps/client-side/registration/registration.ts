import { beginCeremony, toCeremonyError } from '../ceremony/index.js';
import { getCredentialsContainer } from '../environment/index.js';
import { registrationToJSON, toCreationOptions } from '../serialize/index.js';

import type { RegistrationResponseJSON, StartRegistrationOptions } from '@types';

/**
 * Run `navigator.credentials.create()` with options from your server and
 * return JSON ready to POST back for verification.
 *
 * Throws `WebAuthnError` – switch on `error.code`
 * (`CEREMONY_NOT_ALLOWED` = user cancelled / timed out, `CREDENTIAL_EXCLUDED` = already registered…).
 */
export async function startRegistration(
  options: StartRegistrationOptions,
): Promise<RegistrationResponseJSON> {
  const container = getCredentialsContainer();
  const publicKey = toCreationOptions(options.optionsJSON);
  const ceremony = beginCeremony(options.signal);
  try {
    const credential = await container.create({
      publicKey,
      ...(ceremony.signal ? { signal: ceremony.signal } : {}),
      ...(options.useAutoRegister ? { mediation: 'conditional' } : {}),
    });
    if (credential === null) {
      throw toCeremonyError({
        name: 'NotAllowedError',
        message: 'No credential created',
      });
    }
    return registrationToJSON(credential);
  } catch (error) {
    throw toCeremonyError(error, ceremony.signal);
  } finally {
    ceremony.end();
  }
}

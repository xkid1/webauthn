import { describe, test } from 'vitest';

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@apps';

import { config, passkeys, user } from './fixtures.js';

describe('server ceremonies', () => {
  test('options generation', async ({ bench }) => {
    await bench.compare(
      bench('generateRegistrationOptions', () => {
        generateRegistrationOptions(config, { user });
      }),
      bench('generateAuthenticationOptions', () => {
        generateAuthenticationOptions(config);
      }),
    );
  });

  test('verifyRegistrationResponse ("none" attestation) by algorithm', async ({
    bench,
  }) => {
    await bench.compare(
      ...passkeys.map((c) =>
        bench(c.label, async () => {
          await verifyRegistrationResponse(c.config, {
            response: c.registration,
            expectedChallenge: c.registrationChallenge,
          });
        }),
      ),
    );
  });

  test('verifyAuthenticationResponse (sign-in) by algorithm', async ({ bench }) => {
    await bench.compare(
      ...passkeys.map((c) =>
        bench(c.label, async () => {
          await verifyAuthenticationResponse(c.config, {
            response: c.authentication,
            expectedChallenge: c.authenticationChallenge,
            credential: c.credential,
          });
        }),
      ),
    );
  });
});

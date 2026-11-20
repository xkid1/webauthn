import { describe, test } from 'vitest';

import { verifyRegistrationResponse } from '@apps';

import { attestations } from './fixtures.js';

// Full §7.1 registration verification including the attestation statement and,
// where present, X.509 chain validation against a configured trust anchor.
describe('attestation', () => {
  test('verifyRegistrationResponse by attestation format (ES256)', async ({ bench }) => {
    await bench.compare(
      ...attestations.map((c) =>
        bench(c.label, async () => {
          await verifyRegistrationResponse(c.config, {
            response: c.registration,
            expectedChallenge: c.registrationChallenge,
          });
        }),
      ),
    );
  });
});

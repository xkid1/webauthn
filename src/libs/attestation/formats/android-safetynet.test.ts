import { beforeAll, describe, expect, it } from 'vitest';

import {
  attestationContext,
  attestationTrustSuite,
  makeTestRoot,
  rejection,
  safetyNetAttestation,
  verifyStatement,
  type SafetyNetTamper,
  type TestCertificate,
} from '../../../../tests';

import {
  createAndroidSafetyNetVerifier,
  verifyAndroidSafetyNetAttestation,
} from './android-safetynet';

describe('android-safetynet attestation (§8.5)', () => {
  attestationTrustSuite({
    verify: verifyAndroidSafetyNetAttestation,
    type: 'basic',
    build: (root) => safetyNetAttestation(root),
  });

  let root: TestCertificate;
  beforeAll(async () => {
    root = await makeTestRoot();
  });

  it.each<[SafetyNetTamper, RegExp]>([
    ['signature', /JWS signature is invalid/u],
    ['nonce', /nonce does not match/u],
    ['cts', /ctsProfileMatch/u],
    ['stale', /too old/u],
    ['future', /in the future/u],
    ['hostname', /attest\.android\.com/u],
    ['algNone', /unsupported JWS alg/u],
    ['hs256', /unsupported JWS alg/u],
    ['shortSignature', /wrong length/u],
    ['noX5c', /x5c must be a non-empty array/u],
    ['noTimestamp', /timestampMs is missing/u],
  ])('rejects tampered %s', (tamper, message) =>
    expect(
      verifyStatement(
        verifyAndroidSafetyNetAttestation,
        safetyNetAttestation(root, tamper),
      ),
    ).rejects.toMatchObject(rejection(message)),
  );

  it('honours a custom freshness window and validates it', async () => {
    const relaxed = createAndroidSafetyNetVerifier({ maxAgeMs: 300_000 });
    await expect(
      relaxed(await attestationContext(safetyNetAttestation(root, 'stale'))),
    ).resolves.toMatchObject({ type: 'basic' });
    expect(() => createAndroidSafetyNetVerifier({ maxAgeMs: 0 })).toThrow(
      expect.objectContaining({ code: 'INVALID_CONFIG' }) as Error,
    );
  });
});

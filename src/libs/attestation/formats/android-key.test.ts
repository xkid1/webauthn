import { beforeAll, describe, expect, it } from 'vitest';

import {
  androidKeyAttestation,
  type AndroidKeyTamper,
  attestationContext,
  attestationTrustSuite,
  makeTestRoot,
  rejection,
  type TestCertificate,
  verifyStatement,
} from '../../../../tests/index.js';

import { createAndroidKeyVerifier, verifyAndroidKeyAttestation } from './android-key.js';

describe('android-key attestation (§8.4)', () => {
  attestationTrustSuite({
    verify: verifyAndroidKeyAttestation,
    type: 'basic',
    build: (root) => androidKeyAttestation(root),
  });

  let root: TestCertificate;
  beforeAll(async () => {
    root = await makeTestRoot();
  });

  it.each<[AndroidKeyTamper, RegExp]>([
    ['signature', /signature is invalid/u],
    ['challenge', /attestationChallenge/u],
    ['allApplications', /allApplications/u],
    ['origin', /KM_ORIGIN_GENERATED/u],
    ['purpose', /KM_PURPOSE_SIGN/u],
    ['foreignKey', /signature is invalid|does not match credential/u],
    ['conflictingOrigin', /KM_ORIGIN_GENERATED/u],
    ['extraPurpose', /exactly KM_PURPOSE_SIGN/u],
    ['duplicateTag', /duplicate AuthorizationList tag/u],
    ['missingExtension', /missing KeyDescription/u],
    ['extraField', /exactly 8 fields/u],
  ])('rejects tampered %s', (tamper, message) =>
    expect(
      verifyStatement(verifyAndroidKeyAttestation, androidKeyAttestation(root, tamper)),
    ).rejects.toMatchObject(rejection(message)),
  );

  it('accepts softwareEnforced by default but not with requireTeeEnforced', async () => {
    const strict = createAndroidKeyVerifier({ requireTeeEnforced: true });
    const softwareOnly = await attestationContext(
      androidKeyAttestation(root, 'softwareOnly'),
    );
    await expect(verifyAndroidKeyAttestation(softwareOnly)).resolves.toMatchObject({
      type: 'basic',
    });
    await expect(strict(softwareOnly)).rejects.toThrow(/KM_ORIGIN_GENERATED/u);
    await expect(
      strict(await attestationContext(androidKeyAttestation(root))),
    ).resolves.toBeDefined();
  });
});

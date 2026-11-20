import { beforeAll, describe, expect, it } from 'vitest';

import {
  appleAttestation,
  type AppleTamper,
  attestationTrustSuite,
  makeTestRoot,
  rejection,
  type TestCertificate,
  verifyStatement,
} from '../../../../tests/index.js';

import { verifyAppleAttestation } from './apple.js';

describe('apple attestation (§8.8)', () => {
  attestationTrustSuite({
    verify: verifyAppleAttestation,
    type: 'anonca',
    build: (root) => appleAttestation(root),
  });

  let root: TestCertificate;
  beforeAll(async () => {
    root = await makeTestRoot();
  });

  it.each<[AppleTamper, RegExp]>([
    ['nonce', /nonce does not match/u],
    ['foreignKey', /does not match credential/u],
    ['missingExtension', /missing nonce extension/u],
    ['wrongTag', /malformed nonce/u],
  ])('rejects tampered %s', (tamper, message) =>
    expect(
      verifyStatement(verifyAppleAttestation, appleAttestation(root, tamper)),
    ).rejects.toMatchObject(rejection(message)),
  );
});

import { beforeAll, describe, expect, it } from 'vitest';

import {
  attestationContext,
  attestationTrustSuite,
  makeTestRoot,
  rejection,
  type TestCertificate,
  tpmAttestation,
  type TpmTamper,
  verifyStatement,
} from '../../../../tests/index.js';

import { COSEAlgorithm } from '../../cose/index.js';

import { verifyTpmAttestation } from './tpm.js';

describe('tpm attestation (§8.3)', () => {
  attestationTrustSuite({
    verify: verifyTpmAttestation,
    type: 'attca',
    build: (root) => tpmAttestation(root),
  });

  let root: TestCertificate;
  beforeAll(async () => {
    root = await makeTestRoot();
  });

  it.each<[TpmTamper, RegExp]>([
    ['signature', /signature is invalid/u],
    ['extraData', /extraData/u],
    ['name', /attested name/u],
    ['pubAreaKey', /pubArea key/u],
    ['magic', /magic/u],
    ['type', /TPM_ST_ATTEST_CERTIFY/u],
    ['subject', /subject must be empty/u],
    ['eku', /AIKCertificate EKU/u],
    ['sanNotCritical', /SubjectAltName/u],
    ['sanAttrs', /TPM device attributes/u],
    ['manufacturer', /manufacturer/u],
    ['aikCa', /must not be a CA/u],
    ['aaguid', /AAGUID/u],
    ['nameAlgSha1', /nameAlg/u],
    ['trailing', /trailing bytes/u],
    ['ver', /ver must be/u],
  ])('rejects tampered %s', (tamper, message) =>
    expect(
      verifyStatement(verifyTpmAttestation, tpmAttestation(root, tamper)),
    ).rejects.toMatchObject(rejection(message)),
  );

  it('rejects RS1', () =>
    expect(
      verifyStatement(verifyTpmAttestation, tpmAttestation(root, 'rs1')),
    ).rejects.toMatchObject(rejection(/not supported/u, 'UNSUPPORTED_ALGORITHM')));

  it('verifies an RSA pubArea (exponent 0 = 65537) and checks keyBits and n', async () => {
    const rsa = async (tamper?: TpmTamper) =>
      verifyTpmAttestation(
        await attestationContext(tpmAttestation(root, tamper), {
          alg: COSEAlgorithm.RS256,
          trustAnchors: [root.der],
        }),
      );
    await expect(rsa()).resolves.toMatchObject({ type: 'attca', trusted: true });
    await expect(rsa('keyBits')).rejects.toThrow(/keyBits/u);
    await expect(rsa('pubAreaKey')).rejects.toThrow(/pubArea key/u);
  });
});

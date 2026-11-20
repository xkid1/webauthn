import { beforeAll, describe, expect, it } from 'vitest';

import {
  attestationContext,
  makeCertificate,
  makeTestRoot,
  type TestCertificate,
} from '../../../../tests/index.js';

import { verifyFidoU2fAttestation } from './fido-u2f.js';

describe('fido-u2f attestation (§8.6)', () => {
  let root: TestCertificate;
  let leaf: TestCertificate;
  beforeAll(async () => {
    root = await makeTestRoot();
    leaf = await makeCertificate({
      subject: [['2.5.4.3', 'U2F']],
      issuer: root,
      serial: 3,
    });
  });

  it('verifies and chains to the configured anchor', async () => {
    const ctx = await attestationContext(
      { format: 'fido-u2f', attestationChain: [leaf] },
      { trustAnchors: [root.der] },
    );
    await expect(verifyFidoU2fAttestation(ctx)).resolves.toMatchObject({
      type: 'basic',
      trusted: true,
    });
  });

  it('rejects a forged signature', async () => {
    const ctx = await attestationContext({
      format: 'fido-u2f',
      attestationChain: [leaf],
      corruptSignature: true,
    });
    await expect(verifyFidoU2fAttestation(ctx)).rejects.toMatchObject({
      code: 'ATTESTATION_INVALID',
    });
  });
});

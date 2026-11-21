import { webcrypto } from 'node:crypto';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  ATTESTATION_SUBJECT,
  attestationContext,
  makeCertificate,
  makeTestRoot,
  type TestCertificate,
} from '../../../../tests';

import { verifyPackedAttestation } from './packed';

describe('packed attestation (§8.2)', () => {
  const aaguid = webcrypto.getRandomValues(new Uint8Array(16));
  let root: TestCertificate;
  let leaf: TestCertificate;
  beforeAll(async () => {
    root = await makeTestRoot();
    leaf = await makeCertificate({
      subject: ATTESTATION_SUBJECT,
      issuer: root,
      aaguid,
      serial: 2,
    });
  });

  it('self attestation: valid, and rejected when forged', async () => {
    await expect(
      verifyPackedAttestation(await attestationContext({ format: 'packed-self' })),
    ).resolves.toMatchObject({ type: 'self', trusted: false, trustPath: [] });
    await expect(
      verifyPackedAttestation(
        await attestationContext({ format: 'packed-self', corruptSignature: true }),
      ),
    ).rejects.toMatchObject({ code: 'ATTESTATION_INVALID' });
  });

  it('x5c: trusted only with a matching anchor', async () => {
    const statement = { format: 'packed-x5c', attestationChain: [leaf], aaguid } as const;
    await expect(
      verifyPackedAttestation(
        await attestationContext(statement, { trustAnchors: [root.der] }),
      ),
    ).resolves.toMatchObject({ type: 'basic', trusted: true });
    await expect(
      verifyPackedAttestation(await attestationContext(statement)),
    ).resolves.toMatchObject({ type: 'basic', trusted: false });
  });

  it('x5c: rejects an AAGUID mismatch and a forged signature', async () => {
    await expect(
      verifyPackedAttestation(
        await attestationContext({ format: 'packed-x5c', attestationChain: [leaf] }),
      ),
    ).rejects.toThrow(/AAGUID/u);
    await expect(
      verifyPackedAttestation(
        await attestationContext({
          format: 'packed-x5c',
          attestationChain: [leaf],
          aaguid,
          corruptSignature: true,
        }),
      ),
    ).rejects.toMatchObject({ code: 'ATTESTATION_INVALID' });
  });
});

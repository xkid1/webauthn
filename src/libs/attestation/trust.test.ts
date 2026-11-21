import { describe, expect, it } from 'vitest';

import {
  ATTESTATION_SUBJECT,
  testCrypto as crypto,
  makeCertificate,
  makeTestRoot,
  ROOT_SUBJECT,
} from '../../../tests';

import { verifyCertificateChain } from './trust';

describe('verifyCertificateChain', () => {
  it('trusts only chains that end at a valid configured anchor', async () => {
    const root = await makeTestRoot();
    const leaf = await makeCertificate({
      subject: ATTESTATION_SUBJECT,
      issuer: root,
      serial: 2,
    });
    const now = Date.now();

    await expect(
      verifyCertificateChain({
        crypto,
        chain: [leaf.der],
        trustAnchors: [root.der],
        now,
      }),
    ).resolves.toBe(true);
    await expect(
      verifyCertificateChain({ crypto, chain: [leaf.der], trustAnchors: [], now }),
    ).resolves.toBe(false);

    const otherRoot = await makeCertificate({ subject: ROOT_SUBJECT, ca: true });
    await expect(
      verifyCertificateChain({
        crypto,
        chain: [leaf.der],
        trustAnchors: [otherRoot.der],
        now,
      }),
    ).resolves.toBe(false);
    await expect(
      verifyCertificateChain({
        crypto,
        chain: [leaf.der],
        trustAnchors: [root.der],
        now: now + 3 * 365 * 86_400_000,
      }),
    ).rejects.toThrow(/validity/u);
  });

  it('verifies a link where a P-256 CA signs with ecdsa-with-SHA384', async () => {
    const root = await makeTestRoot();
    const leaf = await makeCertificate({
      subject: [['2.5.4.3', 'leaf']],
      issuer: root,
      serial: 50,
      signatureHash: 'SHA-384',
    });
    await expect(
      verifyCertificateChain({
        crypto,
        chain: [leaf.der],
        trustAnchors: [root.der],
        now: Date.now(),
      }),
    ).resolves.toBe(true);
  });
});

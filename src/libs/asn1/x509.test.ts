import { webcrypto } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { WebAuthnError } from '@utils';

import {
  ATTESTATION_SUBJECT,
  makeCertificate,
  makeTestRoot,
  ROOT_SUBJECT,
  testCrypto,
} from '../../../tests';
import { COSEAlgorithm, getAlgorithmSpec } from '../cose';

import {
  getCertificateAaguid,
  importCertificateKey,
  isCertificateAuthority,
  parseCertificate,
} from './x509';

describe('X.509', () => {
  it('parses version, subject, CA flag and the FIDO AAGUID extension', async () => {
    const aaguid = webcrypto.getRandomValues(new Uint8Array(16));
    const root = await makeTestRoot();
    const leaf = await makeCertificate({
      subject: ATTESTATION_SUBJECT,
      issuer: root,
      aaguid,
      serial: 2,
    });

    const parsed = parseCertificate(leaf.der);
    expect(parsed.version).toBe(3);
    expect(parsed.subjectAttributes.get('2.5.4.11')).toBe('Authenticator Attestation');
    expect(isCertificateAuthority(parsed)).toBe(false);
    expect(isCertificateAuthority(parseCertificate(root.der))).toBe(true);
    expect(getCertificateAaguid(parsed)).toEqual(aaguid);
  });

  it('rejects garbage DER', () => {
    expect(() => parseCertificate(Uint8Array.of(0x30, 0x81, 0x05))).toThrow(
      WebAuthnError,
    );
  });

  it('rejects RSA certificate keys below 2048 bits', async () => {
    const weak = await webcrypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    );
    const root = await makeTestRoot();
    const cert = parseCertificate(
      (await makeCertificate({ subject: ROOT_SUBJECT, issuer: root, keyPair: weak })).der,
    );
    await expect(
      importCertificateKey(testCrypto, cert, getAlgorithmSpec(COSEAlgorithm.RS256)!),
    ).rejects.toMatchObject({ code: 'INVALID_PUBLIC_KEY' });
  });
});

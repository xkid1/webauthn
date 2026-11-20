import { concatBytes, copyBytes, timingSafeEqual, WebAuthnError } from '@utils';

import {
  getCertificateAaguid,
  getExtendedKeyUsage,
  getSubjectAltNameDirectoryNames,
  hasEmptySubject,
  importCertificateKey,
  isCertificateAuthority,
  OID,
  parseCertificate,
} from '../../asn1/index.js';
import { getAlgorithmSpec, parseCoseKey } from '../../cose/index.js';
import { verifyWithKey } from '../../crypto/index.js';
import { assertOnlyKeys, stmtBytes, stmtCertificates, stmtNumber } from '../statement.js';
import { verifyCertificateChain } from '../trust.js';

import {
  parseCertInfo,
  parsePubArea,
  TPM_ALG,
  TPM_ECC_CURVE,
  TPM_GENERATED_VALUE,
  TPM_ST_ATTEST_CERTIFY,
} from './tpm-structures.js';

import type {
  AttestationVerifier,
  CosePublicKey,
  CryptoLike,
  HashName,
  TpmPublicKey,
} from '@types';

const invalid = (message: string): never => {
  throw new WebAuthnError('ATTESTATION_INVALID', `tpm: ${message}`);
};

/** TPM nameAlg → WebCrypto digest. SHA-1 names are rejected. */
const NAME_ALG_HASH: ReadonlyMap<number, HashName> = new Map([
  [TPM_ALG.SHA256, 'SHA-256'],
  [TPM_ALG.SHA384, 'SHA-384'],
  [TPM_ALG.SHA512, 'SHA-512'],
] as const);

const CURVE_BY_COSE: ReadonlyMap<number, number> = new Map([
  [1, TPM_ECC_CURVE.NIST_P256],
  [2, TPM_ECC_CURVE.NIST_P384],
  [3, TPM_ECC_CURVE.NIST_P521],
]);

const TPM_MANUFACTURER_ID = /^id:[0-9A-F]{8}$/iu;

const digest = async (crypto: CryptoLike, hash: HashName, data: Uint8Array) =>
  new Uint8Array(await crypto.subtle.digest(hash, copyBytes(data)));

const bytesToNumber = (b: Uint8Array): number => b.reduce((acc, x) => acc * 256 + x, 0);

function pubAreaMatchesCredential(key: TpmPublicKey, cose: CosePublicKey): boolean {
  if (key.type === 'RSA') {
    if (cose.kty !== 'RSA') return false;
    const exponent = key.exponent === 0 ? 65537 : key.exponent;
    return timingSafeEqual(key.n, cose.n) && exponent === bytesToNumber(cose.e);
  }
  if (cose.kty !== 'EC2' || cose.spec.family !== 'ECDSA') return false;
  return (
    CURVE_BY_COSE.get(cose.spec.coseCurve) === key.curveId &&
    timingSafeEqual(key.x, cose.x) &&
    timingSafeEqual(key.y, cose.y)
  );
}

/** WebAuthn §8.3 – "tpm" (TPM 2.0 attestation via an AIK certificate). ECDAA is rejected. */
export const verifyTpmAttestation: AttestationVerifier = async (ctx) => {
  assertOnlyKeys(ctx.attStmt, ['ver', 'alg', 'x5c', 'sig', 'certInfo', 'pubArea']);
  if (ctx.attStmt.get('ver') !== '2.0') invalid('ver must be "2.0"');
  const alg = stmtNumber(ctx.attStmt, 'alg');
  const sig = stmtBytes(ctx.attStmt, 'sig');
  const certInfoBytes = stmtBytes(ctx.attStmt, 'certInfo');
  const pubAreaBytes = stmtBytes(ctx.attStmt, 'pubArea');
  const x5c = stmtCertificates(ctx.attStmt) ?? invalid('missing x5c');
  const credential =
    ctx.parsedAuthData.attestedCredentialData ?? invalid('missing attested credential');

  const spec = getAlgorithmSpec(alg);
  if (!spec)
    throw new WebAuthnError('UNSUPPORTED_ALGORITHM', `tpm: alg ${alg} is not supported`);

  // §8.3.2: the key in pubArea must be the credential public key.
  const pubArea = parsePubArea(pubAreaBytes);
  const cose = parseCoseKey(credential.credentialPublicKey);
  if (!pubAreaMatchesCredential(pubArea.key, cose)) {
    invalid('pubArea key does not match credential public key');
  }

  // §8.3.2: validate certInfo.
  const certInfo = parseCertInfo(certInfoBytes);
  if (certInfo.magic !== TPM_GENERATED_VALUE)
    invalid('certInfo magic is not TPM_GENERATED_VALUE');
  if (certInfo.type !== TPM_ST_ATTEST_CERTIFY)
    invalid('certInfo type is not TPM_ST_ATTEST_CERTIFY');

  if (spec.family === 'EdDSA') return invalid('alg must use a hash function');
  const attToBeSigned = concatBytes(ctx.authData, ctx.clientDataHash);
  const expectedExtra = await digest(ctx.crypto, spec.hash, attToBeSigned);
  if (!timingSafeEqual(certInfo.extraData, expectedExtra)) {
    invalid('certInfo extraData does not match attToBeSigned hash');
  }

  const nameHash =
    NAME_ALG_HASH.get(pubArea.nameAlg) ?? invalid('unsupported pubArea nameAlg');
  const expectedName = concatBytes(
    Uint8Array.of(pubArea.nameAlg >> 8, pubArea.nameAlg & 0xff),
    await digest(ctx.crypto, nameHash, pubAreaBytes),
  );
  if (!timingSafeEqual(certInfo.attestedName, expectedName)) {
    invalid('certInfo attested name does not match pubArea');
  }

  // §8.3.2: sig is a valid signature over certInfo by the AIK certificate.
  const aik = parseCertificate(x5c[0]!);
  const key = await importCertificateKey(ctx.crypto, aik, spec);
  if (
    !(await verifyWithKey({
      crypto: ctx.crypto,
      key,
      spec,
      signature: sig,
      data: certInfoBytes,
    }))
  ) {
    invalid('signature is invalid');
  }

  // §8.3.1 TPM attestation statement certificate requirements.
  if (aik.version !== 3) invalid('AIK certificate must be X.509 v3');
  if (!hasEmptySubject(aik)) invalid('AIK certificate subject must be empty');
  const san = aik.extensions.get(OID.subjectAltName);
  if (!san?.critical)
    invalid('AIK certificate SubjectAltName must be present and critical');
  const tpmName = getSubjectAltNameDirectoryNames(aik).find(
    (n) => n.has(OID.tpmManufacturer) && n.has(OID.tpmModel) && n.has(OID.tpmVersion),
  );
  if (!tpmName)
    return invalid('AIK certificate SubjectAltName lacks TPM device attributes');
  if (!TPM_MANUFACTURER_ID.test(tpmName.get(OID.tpmManufacturer)!)) {
    invalid('AIK certificate TPM manufacturer is malformed');
  }
  if (!getExtendedKeyUsage(aik).includes(OID.tcgKpAikCertificate)) {
    invalid('AIK certificate must have the tcg-kp-AIKCertificate EKU');
  }
  if (isCertificateAuthority(aik)) invalid('AIK certificate must not be a CA');
  const certAaguid = getCertificateAaguid(aik);
  if (certAaguid && !timingSafeEqual(certAaguid, credential.aaguid)) {
    invalid('certificate AAGUID does not match authenticator data');
  }

  const trusted = await verifyCertificateChain({
    crypto: ctx.crypto,
    chain: x5c,
    trustAnchors: ctx.trustAnchors,
    now: ctx.now,
  });
  return { type: 'attca', trustPath: x5c, trusted };
};

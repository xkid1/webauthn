import { concatBytes, timingSafeEqual, WebAuthnError } from '@utils';

import {
  getCertificateAaguid,
  importCertificateKey,
  isCertificateAuthority,
  OID,
  parseCertificate,
} from '../../asn1/index.js';
import { getAlgorithmSpec, parseCoseKey } from '../../cose/index.js';
import { verifyCoseSignature, verifyWithKey } from '../../crypto/index.js';
import { assertOnlyKeys, stmtBytes, stmtCertificates, stmtNumber } from '../statement.js';
import { verifyCertificateChain } from '../trust.js';

import type { AttestationVerifier } from '@types';

const invalid = (message: string): never => {
  throw new WebAuthnError('ATTESTATION_INVALID', `packed: ${message}`);
};

/** WebAuthn §8.2 – "packed" (full / basic and self attestation). ECDAA is rejected. */
export const verifyPackedAttestation: AttestationVerifier = async (ctx) => {
  assertOnlyKeys(ctx.attStmt, ['alg', 'sig', 'x5c']);
  const alg = stmtNumber(ctx.attStmt, 'alg');
  const sig = stmtBytes(ctx.attStmt, 'sig');
  const x5c = stmtCertificates(ctx.attStmt);
  const signed = concatBytes(ctx.authData, ctx.clientDataHash);
  const credential =
    ctx.parsedAuthData.attestedCredentialData ?? invalid('missing attested credential');

  if (!x5c) {
    // Self attestation: signed with the credential private key itself.
    const key = parseCoseKey(credential.credentialPublicKey);
    if (key.alg !== alg) invalid('alg does not match credential public key');
    await verifyCoseSignature({
      crypto: ctx.crypto,
      publicKey: key,
      signature: sig,
      data: signed,
    }).catch(() => invalid('self attestation signature is invalid'));
    return { type: 'self', trustPath: [], trusted: false };
  }

  const spec = getAlgorithmSpec(alg);
  if (!spec)
    throw new WebAuthnError(
      'UNSUPPORTED_ALGORITHM',
      `packed: alg ${alg} is not supported`,
    );
  const leaf = parseCertificate(x5c[0]!);

  // §8.2.1 certificate requirements
  if (leaf.version !== 3) invalid('attestation certificate must be X.509 v3');
  const attrs = leaf.subjectAttributes;
  if (
    !attrs.get(OID.country) ||
    !attrs.get(OID.organization) ||
    !attrs.get(OID.commonName)
  ) {
    invalid('attestation certificate subject is incomplete');
  }
  if (attrs.get(OID.organizationalUnit) !== 'Authenticator Attestation') {
    invalid('attestation certificate OU must be "Authenticator Attestation"');
  }
  if (isCertificateAuthority(leaf)) invalid('attestation certificate must not be a CA');
  const certAaguid = getCertificateAaguid(leaf);
  if (certAaguid && !timingSafeEqual(certAaguid, credential.aaguid)) {
    invalid('certificate AAGUID does not match authenticator data');
  }

  const key = await importCertificateKey(ctx.crypto, leaf, spec);
  if (
    !(await verifyWithKey({
      crypto: ctx.crypto,
      key,
      spec,
      signature: sig,
      data: signed,
    }))
  ) {
    invalid('signature is invalid');
  }

  const trusted = await verifyCertificateChain({
    crypto: ctx.crypto,
    chain: x5c,
    trustAnchors: ctx.trustAnchors,
    now: ctx.now,
  });
  return { type: 'basic', trustPath: x5c, trusted };
};

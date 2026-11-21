import { concatBytes, WebAuthnError } from '@utils';

import { importCertificateKey, parseCertificate } from '../../asn1';
import { COSEAlgorithm, getAlgorithmSpec, parseCoseKey } from '../../cose';
import { verifyWithKey } from '../../crypto';
import { assertOnlyKeys, stmtBytes, stmtCertificates } from '../statement';
import { verifyCertificateChain } from '../trust';

import type { AttestationVerifier } from '@types';

const invalid = (message: string): never => {
  throw new WebAuthnError('ATTESTATION_INVALID', `fido-u2f: ${message}`);
};

/** WebAuthn §8.6 – "fido-u2f" (legacy U2F security keys). */
export const verifyFidoU2fAttestation: AttestationVerifier = async (ctx) => {
  assertOnlyKeys(ctx.attStmt, ['sig', 'x5c']);
  const sig = stmtBytes(ctx.attStmt, 'sig');
  const x5c = stmtCertificates(ctx.attStmt) ?? invalid('missing x5c');
  if (x5c.length !== 1) invalid('x5c must contain exactly one certificate');

  const credential =
    ctx.parsedAuthData.attestedCredentialData ?? invalid('missing attested credential');
  if (credential.aaguid.some((b) => b !== 0)) invalid('AAGUID must be zero');

  const cose = parseCoseKey(credential.credentialPublicKey);
  if (cose.kty !== 'EC2' || cose.alg !== COSEAlgorithm.ES256)
    return invalid('credential key must be ES256');

  const spec = getAlgorithmSpec(COSEAlgorithm.ES256)!;
  const leaf = parseCertificate(x5c[0]!);
  if (leaf.publicKeyCurve !== 'P-256') invalid('attestation key must be P-256');

  const publicKeyU2F = concatBytes(Uint8Array.of(0x04), cose.x, cose.y);
  const data = concatBytes(
    Uint8Array.of(0x00),
    ctx.parsedAuthData.rpIdHash,
    ctx.clientDataHash,
    credential.credentialId,
    publicKeyU2F,
  );
  const key = await importCertificateKey(ctx.crypto, leaf, spec);
  if (!(await verifyWithKey({ crypto: ctx.crypto, key, spec, signature: sig, data }))) {
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

import { concatBytes, sha256, timingSafeEqual, WebAuthnError } from '@utils';

import {
  certificateKeyMatchesCose,
  content,
  expectTag,
  OID,
  parseCertificate,
  readChildren,
  readTlv,
  Tag,
} from '../../asn1/index.js';
import { parseCoseKey } from '../../cose/index.js';
import { assertOnlyKeys, stmtCertificates } from '../statement.js';
import { verifyCertificateChain } from '../trust.js';

import type { AttestationVerifier } from '@types';

const invalid = (message: string): never => {
  throw new WebAuthnError('ATTESTATION_INVALID', `apple: ${message}`);
};

/** Extension 1.2.840.113635.100.8.2: SEQUENCE { [1] EXPLICIT OCTET STRING nonce }. */
function readAppleNonce(value: Uint8Array): Uint8Array {
  const seq = readTlv(value, 0);
  if (seq.end !== value.length) invalid('trailing data after nonce extension');
  const [tagged, extra] = readChildren(
    value,
    expectTag(seq, Tag.SEQUENCE, 'Apple nonce'),
  );
  if (tagged?.tag !== 0xa1 || extra) return invalid('malformed nonce extension');
  const [octets, more] = readChildren(value, tagged);
  if (more) invalid('malformed nonce extension');
  return content(value, expectTag(octets, Tag.OCTET_STRING, 'nonce'));
}

/** WebAuthn §8.8 – "apple" (Apple anonymous attestation). */
export const verifyAppleAttestation: AttestationVerifier = async (ctx) => {
  assertOnlyKeys(ctx.attStmt, ['x5c']);
  const x5c = stmtCertificates(ctx.attStmt) ?? invalid('missing x5c');
  const credential =
    ctx.parsedAuthData.attestedCredentialData ?? invalid('missing attested credential');
  const credCert = parseCertificate(x5c[0]!);

  // §8.8 steps 2–4: nonce = SHA-256(authenticatorData || clientDataHash).
  const expected = await sha256(
    concatBytes(ctx.authData, ctx.clientDataHash),
    ctx.crypto,
  );
  const ext = credCert.extensions.get(OID.appleNonce);
  if (!ext) return invalid('missing nonce extension');
  if (!timingSafeEqual(readAppleNonce(ext.value), expected))
    invalid('nonce does not match');

  // §8.8 step 5: credCert public key is the credential public key.
  if (
    !certificateKeyMatchesCose(credCert, parseCoseKey(credential.credentialPublicKey))
  ) {
    invalid('certificate public key does not match credential public key');
  }

  const trusted = await verifyCertificateChain({
    crypto: ctx.crypto,
    chain: x5c,
    trustAnchors: ctx.trustAnchors,
    now: ctx.now,
  });
  return { type: 'anonca', trustPath: x5c, trusted };
};

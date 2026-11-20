import { concatBytes, timingSafeEqual, WebAuthnError } from '@utils';

import {
  certificateKeyMatchesCose,
  content,
  decodeUnsignedInteger,
  expectTag,
  importCertificateKey,
  OID,
  parseCertificate,
  readChildren,
  readTlv,
  Tag,
} from '../../asn1/index.js';
import { getAlgorithmSpec, parseCoseKey } from '../../cose/index.js';
import { verifyWithKey } from '../../crypto/index.js';
import { assertOnlyKeys, stmtBytes, stmtCertificates, stmtNumber } from '../statement.js';
import { verifyCertificateChain } from '../trust.js';

import type {
  AndroidKeyAuthorizationList,
  AndroidKeyDescription,
  AndroidKeyVerifierOptions,
  AttestationVerifier,
  Tlv,
} from '@types';

const invalid = (message: string): never => {
  throw new WebAuthnError('ATTESTATION_INVALID', `android-key: ${message}`);
};

const ENUMERATED = 0x0a;
/** Android Keymaster / KeyMint authorization tags used by §8.4. */
const KM_TAG = { PURPOSE: 1, ALL_APPLICATIONS: 600, ORIGIN: 702 } as const;
const KM_PURPOSE_SIGN = 2;
const KM_ORIGIN_GENERATED = 0;

function parseAuthorizationList(der: Uint8Array, list: Tlv): AndroidKeyAuthorizationList {
  let purposes: number[] | undefined;
  let origin: number | undefined;
  let allApplications = false;
  const seen = new Set<number>();
  for (const entry of readChildren(
    der,
    expectTag(list, Tag.SEQUENCE, 'AuthorizationList'),
    true,
  )) {
    // Every entry is an EXPLICIT context-specific tag.
    if ((entry.tag & 0xe0) !== 0xa0)
      invalid('AuthorizationList entry is not context-tagged');
    if (seen.has(entry.tagNumber)) invalid('duplicate AuthorizationList tag');
    seen.add(entry.tagNumber);
    if (
      entry.tagNumber !== KM_TAG.PURPOSE &&
      entry.tagNumber !== KM_TAG.ORIGIN &&
      entry.tagNumber !== KM_TAG.ALL_APPLICATIONS
    ) {
      continue;
    }
    const [inner, extra] = readChildren(der, entry);
    if (!inner || extra) invalid('malformed AuthorizationList entry');
    if (entry.tagNumber === KM_TAG.PURPOSE) {
      purposes = readChildren(der, expectTag(inner, Tag.SET, 'purpose')).map((p) =>
        decodeUnsignedInteger(der, expectTag(p, Tag.INTEGER, 'purpose value')),
      );
    } else if (entry.tagNumber === KM_TAG.ORIGIN) {
      origin = decodeUnsignedInteger(der, expectTag(inner, Tag.INTEGER, 'origin'));
    } else {
      allApplications = true;
    }
  }
  return { purposes, origin, allApplications };
}

function parseKeyDescription(der: Uint8Array): AndroidKeyDescription {
  const root = readTlv(der, 0);
  if (root.end !== der.length) invalid('trailing data after KeyDescription');
  const fields = readChildren(der, expectTag(root, Tag.SEQUENCE, 'KeyDescription'));
  if (fields.length !== 8) return invalid('KeyDescription must have exactly 8 fields');
  expectTag(fields[0], Tag.INTEGER, 'attestationVersion');
  expectTag(fields[1], ENUMERATED, 'attestationSecurityLevel');
  expectTag(fields[2], Tag.INTEGER, 'keymasterVersion');
  expectTag(fields[3], ENUMERATED, 'keymasterSecurityLevel');
  const challenge = content(
    der,
    expectTag(fields[4], Tag.OCTET_STRING, 'attestationChallenge'),
  );
  expectTag(fields[5], Tag.OCTET_STRING, 'uniqueId');
  return {
    attestationChallenge: challenge,
    softwareEnforced: parseAuthorizationList(der, fields[6]!),
    teeEnforced: parseAuthorizationList(der, fields[7]!),
  };
}

/**
 * Build an "android-key" verifier (WebAuthn §8.4). The default instance is
 * built in; register a stricter one via `attestationVerifiers['android-key']`.
 */
export function createAndroidKeyVerifier(
  options: AndroidKeyVerifierOptions = {},
): AttestationVerifier {
  const teeOnly = options.requireTeeEnforced ?? false;
  return async (ctx) => {
    assertOnlyKeys(ctx.attStmt, ['alg', 'sig', 'x5c']);
    const alg = stmtNumber(ctx.attStmt, 'alg');
    const sig = stmtBytes(ctx.attStmt, 'sig');
    const x5c = stmtCertificates(ctx.attStmt) ?? invalid('missing x5c');
    const credential =
      ctx.parsedAuthData.attestedCredentialData ?? invalid('missing attested credential');

    const spec = getAlgorithmSpec(alg);
    if (!spec) {
      throw new WebAuthnError(
        'UNSUPPORTED_ALGORITHM',
        `android-key: alg ${alg} is not supported`,
      );
    }
    const leaf = parseCertificate(x5c[0]!);

    // §8.4.1: sig over authenticatorData || clientDataHash with the leaf key.
    const key = await importCertificateKey(ctx.crypto, leaf, spec);
    const signed = concatBytes(ctx.authData, ctx.clientDataHash);
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

    // §8.4.1: the leaf public key is the credential public key.
    if (!certificateKeyMatchesCose(leaf, parseCoseKey(credential.credentialPublicKey))) {
      invalid('certificate public key does not match credential public key');
    }

    // §8.4.1: KeyDescription checks.
    const ext = leaf.extensions.get(OID.androidKeyDescription);
    if (!ext) return invalid('missing KeyDescription extension');
    const desc = parseKeyDescription(ext.value);
    if (!timingSafeEqual(desc.attestationChallenge, ctx.clientDataHash)) {
      invalid('attestationChallenge does not match clientDataHash');
    }
    if (desc.softwareEnforced.allApplications || desc.teeEnforced.allApplications) {
      invalid('key must be scoped to the RP (allApplications present)');
    }
    // §8.4.1: origin == KM_ORIGIN_GENERATED and purpose == KM_PURPOSE_SIGN. A value
    // present in *either* list must never contradict that, even in union mode.
    const all = [desc.teeEnforced, desc.softwareEnforced];
    if (all.some((l) => l.origin !== undefined && l.origin !== KM_ORIGIN_GENERATED)) {
      invalid('key origin must be KM_ORIGIN_GENERATED');
    }
    if (
      all.some(
        (l) =>
          l.purposes !== undefined &&
          (l.purposes.length !== 1 || l.purposes[0] !== KM_PURPOSE_SIGN),
      )
    ) {
      invalid('key purpose must be exactly KM_PURPOSE_SIGN');
    }
    const lists = teeOnly ? [desc.teeEnforced] : all;
    if (!lists.some((l) => l.origin === KM_ORIGIN_GENERATED)) {
      invalid('key origin must be KM_ORIGIN_GENERATED');
    }
    if (!lists.some((l) => l.purposes !== undefined)) {
      invalid('key purpose must be exactly KM_PURPOSE_SIGN');
    }

    const trusted = await verifyCertificateChain({
      crypto: ctx.crypto,
      chain: x5c,
      trustAnchors: ctx.trustAnchors,
      now: ctx.now,
    });
    return { type: 'basic', trustPath: x5c, trusted };
  };
}

/** WebAuthn §8.4 – "android-key" (Android Keystore hardware attestation). */
export const verifyAndroidKeyAttestation: AttestationVerifier =
  createAndroidKeyVerifier();

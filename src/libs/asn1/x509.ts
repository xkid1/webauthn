import { copyBytes, WebAuthnError } from '@utils';

import {
  bitStringBytes,
  content,
  decodeOid,
  decodeString,
  decodeTime,
  expectTag,
  readChildren,
  readTlv,
  Tag,
  whole,
} from './der';
import { CURVE_BY_OID, OID, SIGNATURE_ALGORITHMS } from './oids';
import { MIN_RSA_BITS, modulusBits, parseRsaPublicKey } from './public-key';

import type {
  AlgorithmSpec,
  CryptoKeyLike,
  CryptoLike,
  X509Certificate,
  X509Extension,
} from '@types';

const fail = (message: string): never => {
  throw new WebAuthnError('ASN1_ERROR', `X.509: ${message}`);
};

function parseName(
  der: Uint8Array,
  name: ReturnType<typeof readTlv>,
): Map<string, string> {
  const attrs = new Map<string, string>();
  for (const rdn of readChildren(der, expectTag(name, Tag.SEQUENCE, 'Name'))) {
    for (const atv of readChildren(der, expectTag(rdn, Tag.SET, 'RDN'))) {
      const [type, value] = readChildren(
        der,
        expectTag(atv, Tag.SEQUENCE, 'AttributeTypeAndValue'),
      );
      const oid = decodeOid(content(der, expectTag(type, Tag.OID, 'attribute OID')));
      try {
        attrs.set(oid, decodeString(der, value ?? fail('missing attribute value')));
      } catch {
        // Unsupported string types (e.g. BMPString) are ignored, not fatal.
      }
    }
  }
  return attrs;
}

export function parseCertificate(raw: Uint8Array): X509Certificate {
  const cert = readTlv(raw, 0);
  if (cert.end !== raw.length) fail('trailing data');
  const [tbsTlv, sigAlgTlv, sigTlv, extra] = readChildren(
    raw,
    expectTag(cert, Tag.SEQUENCE, 'Certificate'),
  );
  if (extra) fail('unexpected Certificate field');

  const tbsNode = expectTag(tbsTlv, Tag.SEQUENCE, 'tbsCertificate');
  const fields = readChildren(raw, tbsNode);
  let i = 0;
  let version = 1;
  if (fields[0]?.tag === 0xa0) {
    const [v] = readChildren(raw, fields[0]);
    const vBytes = content(raw, expectTag(v, Tag.INTEGER, 'version'));
    version = (vBytes[0] ?? 0) + 1;
    i = 1;
  }
  expectTag(fields[i], Tag.INTEGER, 'serialNumber');
  expectTag(fields[i + 1], Tag.SEQUENCE, 'signature');
  const issuer = expectTag(fields[i + 2], Tag.SEQUENCE, 'issuer');
  const validity = readChildren(raw, expectTag(fields[i + 3], Tag.SEQUENCE, 'validity'));
  const subject = expectTag(fields[i + 4], Tag.SEQUENCE, 'subject');
  const spkiTlv = expectTag(fields[i + 5], Tag.SEQUENCE, 'subjectPublicKeyInfo');

  const [spkiAlg] = readChildren(raw, spkiTlv);
  const [keyOidTlv, keyParams] = readChildren(
    raw,
    expectTag(spkiAlg, Tag.SEQUENCE, 'AlgorithmIdentifier'),
  );
  const publicKeyAlgorithm = decodeOid(
    content(raw, expectTag(keyOidTlv, Tag.OID, 'key OID')),
  );
  const publicKeyCurve =
    keyParams?.tag === Tag.OID
      ? CURVE_BY_OID.get(decodeOid(content(raw, keyParams)))
      : undefined;

  const extensions = new Map<string, X509Extension>();
  for (const f of fields.slice(i + 6)) {
    if (f.tag !== 0xa3) continue;
    const [extSeq] = readChildren(raw, f);
    for (const ext of readChildren(raw, expectTag(extSeq, Tag.SEQUENCE, 'Extensions'))) {
      const parts = readChildren(raw, expectTag(ext, Tag.SEQUENCE, 'Extension'));
      const oid = decodeOid(content(raw, expectTag(parts[0], Tag.OID, 'extnID')));
      const critical =
        parts.length === 3 &&
        parts[1]?.tag === Tag.BOOLEAN &&
        content(raw, parts[1])[0] !== 0;
      const value = content(
        raw,
        expectTag(parts[parts.length - 1], Tag.OCTET_STRING, 'extnValue'),
      );
      if (extensions.has(oid)) fail('duplicate extension');
      extensions.set(oid, { critical, value });
    }
  }

  const [sigOid] = readChildren(
    raw,
    expectTag(sigAlgTlv, Tag.SEQUENCE, 'signatureAlgorithm'),
  );
  const result: X509Certificate = {
    raw,
    version,
    tbs: whole(raw, tbsNode),
    signatureAlgorithm: decodeOid(
      content(raw, expectTag(sigOid, Tag.OID, 'signature OID')),
    ),
    signature: bitStringBytes(raw, expectTag(sigTlv, Tag.BIT_STRING, 'signatureValue')),
    issuer: whole(raw, issuer),
    subject: whole(raw, subject),
    subjectAttributes: parseName(raw, subject),
    notBefore: decodeTime(raw, validity[0] ?? fail('missing notBefore')),
    notAfter: decodeTime(raw, validity[1] ?? fail('missing notAfter')),
    spki: whole(raw, spkiTlv),
    publicKeyAlgorithm,
    extensions,
  };
  return publicKeyCurve ? { ...result, publicKeyCurve } : result;
}

/** BasicConstraints cA flag (false when the extension is absent). */
export function isCertificateAuthority(cert: X509Certificate): boolean {
  const ext = cert.extensions.get(OID.basicConstraints);
  if (!ext) return false;
  const seq = readTlv(ext.value, 0);
  const [first] = readChildren(
    ext.value,
    expectTag(seq, Tag.SEQUENCE, 'BasicConstraints'),
  );
  return first?.tag === Tag.BOOLEAN && content(ext.value, first)[0] !== 0;
}

/** Value of the FIDO AAGUID extension (16 bytes) when present. */
export function getCertificateAaguid(cert: X509Certificate): Uint8Array | undefined {
  const ext = cert.extensions.get(OID.fidoAaguid);
  if (!ext) return undefined;
  if (ext.critical) fail('AAGUID extension must not be critical');
  const inner = readTlv(ext.value, 0);
  const aaguid = content(ext.value, expectTag(inner, Tag.OCTET_STRING, 'AAGUID'));
  if (aaguid.length !== 16) fail('AAGUID must be 16 bytes');
  return aaguid;
}

/** `true` when the subject Name has no RDNs (`SEQUENCE {}`). */
export const hasEmptySubject = (cert: X509Certificate): boolean =>
  cert.subject.length === 2 && cert.subject[0] === Tag.SEQUENCE && cert.subject[1] === 0;

/** directoryName entries of the SubjectAltName extension, as attribute maps. */
export function getSubjectAltNameDirectoryNames(
  cert: X509Certificate,
): Map<string, string>[] {
  const ext = cert.extensions.get(OID.subjectAltName);
  if (!ext) return [];
  const names = readTlv(ext.value, 0);
  if (names.end !== ext.value.length) fail('trailing data after SubjectAltName');
  const out: Map<string, string>[] = [];
  for (const gn of readChildren(
    ext.value,
    expectTag(names, Tag.SEQUENCE, 'GeneralNames'),
  )) {
    // directoryName [4] EXPLICIT Name
    if (gn.tag !== 0xa4) continue;
    const [inner, extra] = readChildren(ext.value, gn);
    if (!inner || extra) fail('bad directoryName');
    out.push(parseName(ext.value, inner!));
  }
  return out;
}

/** dNSName entries of the SubjectAltName extension. */
export function getSubjectAltNameDnsNames(cert: X509Certificate): string[] {
  const ext = cert.extensions.get(OID.subjectAltName);
  if (!ext) return [];
  const names = readTlv(ext.value, 0);
  if (names.end !== ext.value.length) fail('trailing data after SubjectAltName');
  return readChildren(ext.value, expectTag(names, Tag.SEQUENCE, 'GeneralNames'))
    .filter((gn) => gn.tag === 0x82)
    .map((gn) => String.fromCharCode(...content(ext.value, gn)));
}

/** Key purpose OIDs from the ExtendedKeyUsage extension (empty when absent). */
export function getExtendedKeyUsage(cert: X509Certificate): string[] {
  const ext = cert.extensions.get(OID.extKeyUsage);
  if (!ext) return [];
  const seq = readTlv(ext.value, 0);
  if (seq.end !== ext.value.length) fail('trailing data after ExtendedKeyUsage');
  return readChildren(ext.value, expectTag(seq, Tag.SEQUENCE, 'ExtKeyUsageSyntax')).map(
    (k) => decodeOid(content(ext.value, expectTag(k, Tag.OID, 'KeyPurposeId'))),
  );
}

export const signatureSpecFor = (cert: X509Certificate): AlgorithmSpec | undefined =>
  SIGNATURE_ALGORITHMS.get(cert.signatureAlgorithm);

/** Import a certificate's public key for verifying signatures made with `spec`. */
export async function importCertificateKey(
  crypto: CryptoLike,
  cert: X509Certificate,
  spec: AlgorithmSpec,
): Promise<CryptoKeyLike> {
  let params: Record<string, unknown>;
  if (spec.family === 'ECDSA') {
    if (cert.publicKeyAlgorithm !== OID.ecPublicKey || !cert.publicKeyCurve)
      fail('expected EC key');
    params = { name: 'ECDSA', namedCurve: cert.publicKeyCurve };
  } else if (spec.family === 'EdDSA') {
    if (cert.publicKeyAlgorithm !== OID.ed25519) fail('expected Ed25519 key');
    params = { name: 'Ed25519' };
  } else {
    if (cert.publicKeyAlgorithm !== OID.rsaEncryption) fail('expected RSA key');
    if (modulusBits(parseRsaPublicKey(cert.spki).n) < MIN_RSA_BITS) {
      throw new WebAuthnError(
        'INVALID_PUBLIC_KEY',
        `Certificate RSA key is below ${MIN_RSA_BITS} bits`,
      );
    }
    params = { name: spec.family, hash: { name: spec.hash } };
  }
  try {
    return await crypto.subtle.importKey('spki', copyBytes(cert.spki), params, false, [
      'verify',
    ]);
  } catch (cause) {
    throw new WebAuthnError(
      'INVALID_PUBLIC_KEY',
      'Unable to import certificate public key',
      {
        cause,
      },
    );
  }
}

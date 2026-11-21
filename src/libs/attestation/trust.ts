import { timingSafeEqual, WebAuthnError } from '@utils';

import {
  importCertificateKey,
  isCertificateAuthority,
  parseCertificate,
  signatureSpecFor,
} from '../asn1';
import { verifyWithKey } from '../crypto';

import type { CertificateChainOptions, CryptoLike, X509Certificate } from '@types';

const ECDSA_SIZE = { 'P-256': 32, 'P-384': 48, 'P-521': 66 } as const;

const untrusted = (message: string): never => {
  throw new WebAuthnError('ATTESTATION_INVALID', `certificate chain: ${message}`);
};

export function assertValidAt(cert: X509Certificate, now: number): void {
  if (now < cert.notBefore || now > cert.notAfter)
    untrusted('certificate is not within its validity period');
}

/** Verify that `subject` was signed by `issuer`'s key. */
export async function isSignedBy(
  crypto: CryptoLike,
  subject: X509Certificate,
  issuer: X509Certificate,
): Promise<boolean> {
  if (!timingSafeEqual(subject.issuer, issuer.subject)) return false;
  const oidSpec = signatureSpecFor(subject);
  if (!oidSpec) return false;
  // The signature OID only names the hash (e.g. ecdsa-with-SHA384); the curve
  // and scalar size come from the issuer key (a P-256 CA may sign with SHA-384).
  let spec = oidSpec;
  if (oidSpec.family === 'ECDSA') {
    const curve = issuer.publicKeyCurve;
    if (!curve) return false;
    spec = { ...oidSpec, curve, size: ECDSA_SIZE[curve] };
  }
  try {
    const key = await importCertificateKey(crypto, issuer, spec);
    return await verifyWithKey({
      crypto,
      key,
      spec,
      signature: subject.signature,
      data: subject.tbs,
    });
  } catch {
    return false;
  }
}

/**
 * Validate an attestation chain (leaf first) against DER trust anchors.
 *
 * Checks: validity windows, issuer/subject linkage, signatures, CA flag on
 * intermediates, and termination at a configured anchor. Revocation (CRL/OCSP)
 * is intentionally out of scope – use FIDO MDS status reports for that.
 *
 * Returns `true` when the chain terminates at an anchor, `false` when no
 * anchors are configured; throws when a chain is present but broken.
 */
export async function verifyCertificateChain(
  options: CertificateChainOptions,
): Promise<boolean> {
  const { crypto, now } = options;
  const certs = options.chain.map(parseCertificate);
  for (const cert of certs) assertValidAt(cert, now);

  for (let i = 0; i + 1 < certs.length; i += 1) {
    const issuer = certs[i + 1]!;
    if (!isCertificateAuthority(issuer)) untrusted('intermediate is not a CA');
    if (!(await isSignedBy(crypto, certs[i]!, issuer)))
      untrusted('broken signature link');
  }

  if (options.trustAnchors.length === 0) return false;

  const last = certs[certs.length - 1]!;
  for (const anchorDer of options.trustAnchors) {
    if (timingSafeEqual(anchorDer, last.raw)) return true;
    const anchor = parseCertificate(anchorDer);
    if (now < anchor.notBefore || now > anchor.notAfter) continue;
    if (await isSignedBy(crypto, last, anchor)) return true;
  }
  return false;
}

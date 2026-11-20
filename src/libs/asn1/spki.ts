import { concatBytes, timingSafeEqual } from '@utils';

import { OID } from './oids.js';
import { parseRsaPublicKey, subjectPublicKey } from './public-key.js';

import type { CosePublicKey, X509Certificate } from '@types';

/**
 * `true` when the certificate's subject public key is exactly the credential
 * public key (same type, curve and key material).
 */
export function certificateKeyMatchesCose(
  cert: X509Certificate,
  cose: CosePublicKey,
): boolean {
  switch (cose.kty) {
    case 'EC2':
      if (cert.publicKeyAlgorithm !== OID.ecPublicKey) return false;
      if (cose.spec.family !== 'ECDSA' || cert.publicKeyCurve !== cose.spec.curve)
        return false;
      return timingSafeEqual(
        subjectPublicKey(cert.spki),
        concatBytes(Uint8Array.of(0x04), cose.x, cose.y),
      );
    case 'OKP':
      return (
        cert.publicKeyAlgorithm === OID.ed25519 &&
        timingSafeEqual(subjectPublicKey(cert.spki), cose.x)
      );
    case 'RSA': {
      if (cert.publicKeyAlgorithm !== OID.rsaEncryption) return false;
      const { n, e } = parseRsaPublicKey(cert.spki);
      return timingSafeEqual(n, cose.n) && timingSafeEqual(e, cose.e);
    }
  }
}

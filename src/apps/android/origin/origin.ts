import { fromBase64Url, fromHex, toBase64Url, toHex, WebAuthnError } from '@utils';

const PREFIX = 'android:apk-key-hash:';

/**
 * Convert an APK signing-certificate SHA-256 fingerprint
 * ("FA:C6:17:…", as printed by `keytool -list -v` / Play Console) into the
 * origin Android places in clientDataJSON. Add it to your server `origins`.
 */
export function androidOriginFromFingerprint(sha256Fingerprint: string): string {
  const bytes = fromHex(sha256Fingerprint);
  if (bytes.length !== 32) {
    throw new WebAuthnError(
      'INVALID_INPUT',
      'Expected a 32-byte SHA-256 certificate fingerprint',
    );
  }
  return `${PREFIX}${toBase64Url(bytes)}`;
}

export const isAndroidOrigin = (origin: string): boolean =>
  origin.startsWith(PREFIX) && /^[A-Za-z0-9_-]{43}$/u.test(origin.slice(PREFIX.length));

/** Inverse of `androidOriginFromFingerprint` – handy for logging / debugging. */
export function fingerprintFromAndroidOrigin(origin: string): string {
  if (!isAndroidOrigin(origin))
    throw new WebAuthnError('INVALID_INPUT', 'Not an android:apk-key-hash origin');
  return toHex(fromBase64Url(origin.slice(PREFIX.length)))
    .toUpperCase()
    .replace(/(..)(?!$)/gu, '$1:');
}

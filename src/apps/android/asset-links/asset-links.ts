import { fromHex, toHex, WebAuthnError } from '@utils';

import type { AssetLinksInput, AssetLinkStatement } from '@types';

/** Java package: ≥ 2 dot-separated segments, each `[A-Za-z][A-Za-z0-9_]*`. */
const isPackageName = (name: string): boolean => {
  const parts = name.split('.');
  return parts.length >= 2 && parts.every((p) => /^[A-Za-z][A-Za-z0-9_]*$/u.test(p));
};

const normaliseFingerprint = (fp: string): string => {
  const bytes = fromHex(fp);
  if (bytes.length !== 32)
    throw new WebAuthnError('INVALID_INPUT', `Invalid SHA-256 fingerprint "${fp}"`);
  return toHex(bytes)
    .toUpperCase()
    .replace(/(..)(?!$)/gu, '$1:');
};

/**
 * Build the Digital Asset Links document to serve at
 * `https://<rpId>/.well-known/assetlinks.json` (Content-Type: application/json).
 * This is what lets your Android app use passkeys for your rpId.
 */
export function buildAssetLinks(apps: readonly AssetLinksInput[]): AssetLinkStatement[] {
  if (apps.length === 0)
    throw new WebAuthnError('INVALID_INPUT', 'At least one app is required');
  return apps.map((app) => {
    if (!isPackageName(app.packageName)) {
      throw new WebAuthnError(
        'INVALID_INPUT',
        `Invalid Android package name "${app.packageName}"`,
      );
    }
    if (app.sha256CertFingerprints.length === 0) {
      throw new WebAuthnError(
        'INVALID_INPUT',
        'At least one certificate fingerprint is required',
      );
    }
    const relation = ['delegate_permission/common.handle_all_urls'];
    if (app.includeLoginCredentials ?? true)
      relation.push('delegate_permission/common.get_login_creds');
    return {
      relation,
      target: {
        namespace: 'android_app',
        package_name: app.packageName,
        sha256_cert_fingerprints: app.sha256CertFingerprints.map(normaliseFingerprint),
      },
    };
  });
}

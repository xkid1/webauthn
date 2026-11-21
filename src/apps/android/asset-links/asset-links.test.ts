import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { buildAssetLinks } from './asset-links';

const FINGERPRINT = createHash('sha256')
  .update('release-key')
  .digest('hex')
  .toUpperCase()
  .replace(/(..)(?!$)/gu, '$1:');

describe('buildAssetLinks', () => {
  it('builds assetlinks.json', () => {
    const links = buildAssetLinks([
      {
        packageName: 'com.example.app',
        sha256CertFingerprints: [FINGERPRINT.toLowerCase()],
      },
    ]);
    expect(links).toEqual([
      {
        relation: [
          'delegate_permission/common.handle_all_urls',
          'delegate_permission/common.get_login_creds',
        ],
        target: {
          namespace: 'android_app',
          package_name: 'com.example.app',
          sha256_cert_fingerprints: [FINGERPRINT],
        },
      },
    ]);
    expect(() =>
      buildAssetLinks([{ packageName: 'bad', sha256CertFingerprints: [FINGERPRINT] }]),
    ).toThrow();
    expect(() => buildAssetLinks([])).toThrow();
  });
});

import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  androidOriginFromFingerprint,
  fingerprintFromAndroidOrigin,
  isAndroidOrigin,
} from './origin';

const FINGERPRINT = createHash('sha256')
  .update('release-key')
  .digest('hex')
  .toUpperCase()
  .replace(/(..)(?!$)/gu, '$1:');
const ANDROID_ORIGIN = androidOriginFromFingerprint(FINGERPRINT);

describe('Android apk-key-hash origins', () => {
  it('derives the apk-key-hash origin and back', () => {
    expect(isAndroidOrigin(ANDROID_ORIGIN)).toBe(true);
    expect(ANDROID_ORIGIN).toBe(
      `android:apk-key-hash:${createHash('sha256').update('release-key').digest('base64url')}`,
    );
    expect(fingerprintFromAndroidOrigin(ANDROID_ORIGIN)).toBe(FINGERPRINT);
    expect(() => androidOriginFromFingerprint('AB:CD')).toThrow();
    expect(isAndroidOrigin('https://example.com')).toBe(false);
  });
});

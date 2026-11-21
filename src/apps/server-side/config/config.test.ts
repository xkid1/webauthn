import { describe, expect, it } from 'vitest';

import { TEST_RP as base } from '../../../../tests';

import { resolveConfig } from './config';

import type { RelyingPartyConfig } from '@types';

describe('resolveConfig', () => {
  it('applies secure defaults', () => {
    const c = resolveConfig(base);
    expect(c).toMatchObject({
      timeout: 300_000,
      userVerification: 'preferred',
      requireUserVerification: false,
      attestation: 'none',
      supportedAlgorithms: [-8, -7, -257],
      challengeSize: 32,
      counterPolicy: 'strict',
      allowCrossOrigin: false,
    });
    expect(Object.isFrozen(c)).toBe(true);
    expect(
      resolveConfig({ ...base, userVerification: 'required' }).requireUserVerification,
    ).toBe(true);
  });

  it.each<[string, Partial<RelyingPartyConfig>]>([
    ['scheme in rpId', { rpId: 'https://example.com' }],
    ['http origin', { origins: ['http://example.com'] }],
    ['origin outside rpId', { origins: ['https://evil.com'] }],
    ['empty origins', { origins: [] }],
    ['tiny challenge', { challengeSize: 8 }],
    ['RS1', { supportedAlgorithms: [-65535] }],
    ['cross origin without allowlist', { allowCrossOrigin: true }],
    ['timeout too long', { timeout: 3_600_000 }],
    ['trusted attestation without anchors', { requireTrustedAttestation: true }],
  ])('rejects %s', (_label, patch) => {
    expect(() => resolveConfig({ ...base, ...patch })).toThrow(
      expect.objectContaining({ code: 'INVALID_CONFIG' }) as Error,
    );
  });

  it('accepts subdomain and Android origins', () => {
    expect(() =>
      resolveConfig({
        ...base,
        origins: ['https://login.example.com', `android:apk-key-hash:${'a'.repeat(43)}`],
      }),
    ).not.toThrow();
  });
});

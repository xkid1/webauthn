import { describe, expect, it } from 'vitest';

import { concatBytes, WebAuthnError } from '@utils';

import { parseAuthenticatorData } from './parse.js';

describe('parseAuthenticatorData', () => {
  const header = (flags: number) =>
    concatBytes(new Uint8Array(32), Uint8Array.of(flags), Uint8Array.of(0, 0, 0, 7));

  it('parses flags and counter', () => {
    const parsed = parseAuthenticatorData(header(0x1d));
    expect(parsed.signCount).toBe(7);
    expect(parsed.flags).toMatchObject({
      userPresent: true,
      userVerified: true,
      backupEligible: true,
      backedUp: true,
    });
  });

  it('rejects BS without BE, truncation and trailing bytes', () => {
    expect(() => parseAuthenticatorData(header(0x11))).toThrow(
      expect.objectContaining({ code: 'INVALID_FLAGS' }) as Error,
    );
    expect(() => parseAuthenticatorData(new Uint8Array(36))).toThrow(WebAuthnError);
    expect(() =>
      parseAuthenticatorData(concatBytes(header(0x01), Uint8Array.of(0))),
    ).toThrow(/trailing/u);
    expect(() => parseAuthenticatorData(header(0x41))).toThrow(/truncated/u);
  });
});

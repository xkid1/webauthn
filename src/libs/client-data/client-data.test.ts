import { describe, expect, it } from 'vitest';

import { toBase64Url, utf8Encode, WebAuthnError } from '@utils';

import { parseClientDataJSON, verifyClientData } from './client-data.js';

describe('clientDataJSON', () => {
  const encode = (value: unknown) => toBase64Url(utf8Encode(JSON.stringify(value)));
  const challenge = toBase64Url(new Uint8Array(32).fill(7));
  const origin = 'https://example.com';
  const expectations = {
    type: 'webauthn.get' as const,
    challenge,
    origins: [origin],
    allowCrossOrigin: false,
    allowedTopOrigins: [],
  };

  it('accepts matching data', () => {
    const ok = parseClientDataJSON(encode({ type: 'webauthn.get', challenge, origin }));
    expect(() => {
      verifyClientData(ok.data, expectations);
    }).not.toThrow();
  });

  it.each<[Record<string, unknown>, string]>([
    [{ type: 'webauthn.create', challenge, origin }, 'TYPE_MISMATCH'],
    [{ type: 'webauthn.get', challenge: 'AAAA', origin }, 'CHALLENGE_MISMATCH'],
    [{ type: 'webauthn.get', challenge: '!!', origin }, 'CHALLENGE_MISMATCH'],
    [{ type: 'webauthn.get', challenge, origin: 'https://evil.com' }, 'ORIGIN_MISMATCH'],
    [
      { type: 'webauthn.get', challenge, origin, crossOrigin: true },
      'CROSS_ORIGIN_NOT_ALLOWED',
    ],
  ])('rejects %o with %s', (data, code) => {
    expect(() => {
      verifyClientData(parseClientDataJSON(encode(data)).data, expectations);
    }).toThrow(expect.objectContaining({ code }) as Error);
  });

  it('rejects malformed JSON shapes', () => {
    expect(() => parseClientDataJSON(toBase64Url(utf8Encode('not json')))).toThrow(
      WebAuthnError,
    );
    expect(() =>
      parseClientDataJSON(encode({ type: 'other', challenge, origin: 'x' })),
    ).toThrow(WebAuthnError);
    expect(() => parseClientDataJSON(encode([1]))).toThrow(WebAuthnError);
  });
});

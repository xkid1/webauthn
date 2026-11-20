import { describe, expect, it } from 'vitest';

import { isValidOrigin, isValidRpId } from './guards.js';

describe('guards', () => {
  it.each([
    ['example.com', true],
    ['login.example.co.uk', true],
    ['localhost', true],
    ['Example.com', false],
    ['https://example.com', false],
    ['example.com:443', false],
    ['127.0.0.1', false],
    ['-bad.com', false],
  ])('isValidRpId(%s) = %s', (rpId, expected) => {
    expect(isValidRpId(rpId)).toBe(expected);
  });

  it.each([
    ['https://example.com', true],
    ['https://login.example.com:8443', true],
    ['http://localhost:3000', true],
    ['http://example.com', false],
    ['https://example.com/', false],
    ['android:apk-key-hash:' + 'A'.repeat(43), true],
    ['file://', false],
  ])('isValidOrigin(%s) = %s', (origin, expected) => {
    expect(isValidOrigin(origin)).toBe(expected);
  });
});

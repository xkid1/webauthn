import { describe, expect, it } from 'vitest';

import { ensure, isWebAuthnError, WebAuthnError } from './error';
import { ERROR_HINTS, getErrorHint } from './hints';

import type { WebAuthnErrorCode } from '@types';

describe('WebAuthnError', () => {
  it('carries code, message, default hint and cause', () => {
    const cause = new Error('DOMException: NotAllowedError');
    const error = new WebAuthnError('ORIGIN_MISMATCH', 'origin is not allowed', {
      cause,
    });
    expect(error).toBeInstanceOf(Error);
    expect(error).toMatchObject({
      name: 'WebAuthnError',
      code: 'ORIGIN_MISMATCH',
      message: 'origin is not allowed',
      hint: ERROR_HINTS.ORIGIN_MISMATCH,
      cause,
    });
    expect(new WebAuthnError('INVALID_INPUT', 'x')).not.toHaveProperty('cause');
  });

  it('accepts a custom hint', () => {
    expect(new WebAuthnError('INVALID_CONFIG', 'x', { hint: 'Set rpId.' }).hint).toBe(
      'Set rpId.',
    );
  });

  it('serialises safely: no cause, no stack', () => {
    const error = new WebAuthnError('SIGNATURE_INVALID', 'bad signature', {
      cause: new Error('internal detail'),
    });
    const json: unknown = JSON.parse(JSON.stringify(error));
    expect(json).toEqual({
      name: 'WebAuthnError',
      code: 'SIGNATURE_INVALID',
      message: 'bad signature',
      hint: ERROR_HINTS.SIGNATURE_INVALID,
    });
  });

  it('formats with code and hint', () => {
    const text = String(new WebAuthnError('CHALLENGE_NOT_FOUND', 'expired'));
    expect(text).toBe(
      `WebAuthnError [CHALLENGE_NOT_FOUND]: expired Hint: ${ERROR_HINTS.CHALLENGE_NOT_FOUND}`,
    );
  });
});

describe('isWebAuthnError', () => {
  const error = new WebAuthnError('COUNTER_REGRESSION', 'counter did not increase');

  it('narrows by type and optional codes', () => {
    expect(isWebAuthnError(error)).toBe(true);
    expect(isWebAuthnError(error, 'COUNTER_REGRESSION')).toBe(true);
    expect(isWebAuthnError(error, 'CHALLENGE_MISMATCH', 'COUNTER_REGRESSION')).toBe(true);
    expect(isWebAuthnError(error, 'CHALLENGE_MISMATCH')).toBe(false);
    expect(isWebAuthnError(new Error('x'))).toBe(false);
    expect(isWebAuthnError({ code: 'COUNTER_REGRESSION' })).toBe(false);
  });
});

describe('ensure', () => {
  it('throws only when the condition is falsy', () => {
    expect(() => ensure(true, 'INVALID_INPUT', 'x')).not.toThrow();
    expect(() => ensure(0, 'INVALID_INPUT', 'must be set')).toThrow(
      expect.objectContaining({ code: 'INVALID_INPUT', message: 'must be set' }) as Error,
    );
  });
});

describe('ERROR_HINTS', () => {
  it('has a non-empty, secret-free hint for every code', () => {
    const codes = Object.keys(ERROR_HINTS) as WebAuthnErrorCode[];
    expect(codes.length).toBeGreaterThan(30);
    for (const code of codes) {
      expect(getErrorHint(code).length).toBeGreaterThan(20);
      expect(Object.isFrozen(ERROR_HINTS)).toBe(true);
    }
  });
});

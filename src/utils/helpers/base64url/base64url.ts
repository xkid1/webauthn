import { WebAuthnError } from '../error/index.js';

import type { Base64URLString } from '@types';

/**
 * Strict RFC 4648 §5 base64url codec. Pure TypeScript – no atob/btoa/Buffer –
 * so it behaves identically in browsers, Node, Electron and Hermes.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const LOOKUP: Int16Array = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i += 1) table[ALPHABET.charCodeAt(i)] = i;
  return table;
})();

export function toBase64Url(bytes: Uint8Array): Base64URLString {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out +=
      ALPHABET[(n >> 18) & 63]! +
      ALPHABET[(n >> 12) & 63]! +
      ALPHABET[(n >> 6) & 63]! +
      ALPHABET[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out +=
      ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

/**
 * Decode base64url. Rejects padding-free invalid lengths, characters outside
 * the URL-safe alphabet, and non-canonical trailing bits. Standard base64
 * (`+`, `/`, `=`) is accepted only when `lenient` is set (some Android
 * bridges emit it).
 */
export function fromBase64Url(input: string, { lenient = false } = {}): Uint8Array {
  if (typeof input !== 'string') {
    throw new WebAuthnError('ENCODING_ERROR', 'base64url input must be a string');
  }
  let s = input;
  if (lenient) s = s.replace(/=+$/u, '').replace(/\+/gu, '-').replace(/\//gu, '_');
  if (s.length % 4 === 1)
    throw new WebAuthnError('ENCODING_ERROR', 'Invalid base64url length');

  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    const value = code < 128 ? LOOKUP[code]! : -1;
    if (value < 0)
      throw new WebAuthnError('ENCODING_ERROR', 'Invalid base64url character');
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o] = (buffer >> bits) & 0xff;
      o += 1;
    }
  }
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
    throw new WebAuthnError('ENCODING_ERROR', 'Non-canonical base64url encoding');
  }
  return out;
}

export function isBase64Url(value: unknown): value is Base64URLString {
  return (
    typeof value === 'string' && /^[A-Za-z0-9_-]*$/u.test(value) && value.length % 4 !== 1
  );
}

/** Accept either raw bytes or base64url and always return bytes. */
export const toBytes = (value: Uint8Array | Base64URLString): Uint8Array =>
  typeof value === 'string' ? fromBase64Url(value) : value;

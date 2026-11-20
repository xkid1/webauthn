import { WebAuthnError } from '../error/index.js';

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Constant-time equality for secrets (challenges, hashes). Runtime depends
 * only on the lengths, never on where the first difference is.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const length = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Copy into a fresh ArrayBuffer-backed view (safe to hand to platform APIs). */
export const copyBytes = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(bytes.length);
  out.set(bytes);
  return out;
};

export const bufferToBytes = (buffer: ArrayBuffer | ArrayBufferView): Uint8Array =>
  buffer instanceof ArrayBuffer
    ? new Uint8Array(buffer.slice(0))
    : new Uint8Array(
        buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength),
      );

export const readUint16BE = (b: Uint8Array, offset: number): number =>
  ((b[offset] ?? 0) << 8) | (b[offset + 1] ?? 0);

export const readUint32BE = (b: Uint8Array, offset: number): number =>
  (((b[offset] ?? 0) << 24) |
    ((b[offset + 1] ?? 0) << 16) |
    ((b[offset + 2] ?? 0) << 8) |
    (b[offset + 3] ?? 0)) >>>
  0;

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/[\s:]/gu, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/u.test(clean)) {
    throw new WebAuthnError('ENCODING_ERROR', 'Invalid hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1)
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Format 16 bytes as a lowercase RFC 4122 UUID string. */
export function formatUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16)
    throw new WebAuthnError('ENCODING_ERROR', 'UUID must be 16 bytes');
  const h = toHex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

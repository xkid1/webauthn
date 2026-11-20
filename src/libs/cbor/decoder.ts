import { utf8Decode, WebAuthnError } from '@utils';

import type { CborDecodeOptions, CborDecodeResult, CborMap, CborValue } from '@types';

/**
 * Hardened CBOR (RFC 8949) decoder for the WebAuthn subset.
 *
 * Security properties:
 *  - every length is checked against remaining input before allocating
 *  - nesting depth and item count are bounded (no stack / memory exhaustion)
 *  - indefinite-length items, tags, reserved and half-float encodings are rejected
 *  - duplicate map keys are rejected
 *  - `decodeCbor` rejects trailing bytes
 */

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

class Reader {
  offset = 0;
  items = 0;

  constructor(
    readonly bytes: Uint8Array,
    readonly maxDepth: number,
    readonly maxItems: number,
  ) {}

  fail(message: string): never {
    throw new WebAuthnError('CBOR_ERROR', `CBOR: ${message} at offset ${this.offset}`);
  }

  take(length: number): Uint8Array {
    if (length > this.bytes.length - this.offset) this.fail('unexpected end of input');
    const out = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  byte(): number {
    const b = this.bytes[this.offset];
    if (b === undefined) this.fail('unexpected end of input');
    this.offset += 1;
    return b;
  }

  /** Read the argument for additional-info `info`. Returns number or bigint. */
  argument(info: number): number | bigint {
    if (info < 24) return info;
    if (info === 24) return this.byte();
    if (info === 25) return (this.byte() << 8) | this.byte();
    if (info === 26) {
      return (
        ((this.byte() << 24) | (this.byte() << 16) | (this.byte() << 8) | this.byte()) >>>
        0
      );
    }
    if (info === 27) {
      let value = 0n;
      for (let i = 0; i < 8; i += 1) value = (value << 8n) | BigInt(this.byte());
      return value <= MAX_SAFE ? Number(value) : value;
    }
    if (info === 31) return this.fail('indefinite-length items are not allowed');
    return this.fail(`reserved additional info ${info}`);
  }

  length(info: number): number {
    const value = this.argument(info);
    if (typeof value === 'bigint') return this.fail('length too large');
    return value;
  }

  value(depth: number): CborValue {
    if (depth > this.maxDepth) this.fail('maximum nesting depth exceeded');
    this.items += 1;
    if (this.items > this.maxItems) this.fail('maximum item count exceeded');

    const initial = this.byte();
    const major = initial >> 5;
    const info = initial & 31;

    switch (major) {
      case 0:
        return this.argument(info);
      case 1: {
        const n = this.argument(info);
        if (typeof n === 'bigint') return -1n - n;
        return n === Number.MAX_SAFE_INTEGER ? -1n - BigInt(n) : -1 - n;
      }
      case 2:
        return this.take(this.length(info));
      case 3:
        return utf8Decode(this.take(this.length(info)));
      case 4: {
        const count = this.length(info);
        if (count > this.bytes.length - this.offset) this.fail('array longer than input');
        const out: CborValue[] = [];
        for (let i = 0; i < count; i += 1) out.push(this.value(depth + 1));
        return out;
      }
      case 5: {
        const count = this.length(info);
        if (count * 2 > this.bytes.length - this.offset)
          this.fail('map longer than input');
        const out: CborMap = new Map();
        for (let i = 0; i < count; i += 1) {
          const key = this.value(depth + 1);
          if (key instanceof Uint8Array || Array.isArray(key) || key instanceof Map) {
            this.fail('only integer and text map keys are supported');
          }
          if (out.has(key)) this.fail('duplicate map key');
          out.set(key, this.value(depth + 1));
        }
        return out;
      }
      case 6:
        return this.fail('tags are not supported');
      default:
        return this.simple(info);
    }
  }

  simple(info: number): CborValue {
    switch (info) {
      case 20:
        return false;
      case 21:
        return true;
      case 22:
        return null;
      case 23:
        return undefined;
      case 26:
        return new DataView(this.take(4).buffer).getFloat32(0);
      case 27:
        return new DataView(this.take(8).buffer).getFloat64(0);
      default:
        return this.fail(`unsupported simple value ${info}`);
    }
  }
}

/** Decode the first CBOR item and report how many bytes it consumed. */
export function decodeCborFirst(
  bytes: Uint8Array,
  options: CborDecodeOptions = {},
): CborDecodeResult {
  const reader = new Reader(bytes, options.maxDepth ?? 16, options.maxItems ?? 4096);
  const value = reader.value(0);
  return { value, length: reader.offset };
}

/** Decode exactly one CBOR item; trailing bytes are an error. */
export function decodeCbor(
  bytes: Uint8Array,
  options: CborDecodeOptions = {},
): CborValue {
  const { value, length } = decodeCborFirst(bytes, options);
  if (length !== bytes.length) {
    throw new WebAuthnError('CBOR_ERROR', 'CBOR: unexpected trailing bytes');
  }
  return value;
}

export const isCborMap = (value: CborValue): value is CborMap => value instanceof Map;

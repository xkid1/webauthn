/**
 * Minimal structural types for the platform APIs we touch. Declaring them here
 * keeps the published `.d.ts` free of DOM / Node lib dependencies, so the
 * package type-checks in browsers, Node, Electron and React Native alike.
 */

/** Opaque WebCrypto key handle. */
export interface CryptoKeyLike {
  readonly type: string;
}

export interface SubtleCryptoLike {
  importKey(
    format: 'jwk' | 'spki' | 'raw',
    keyData: unknown,
    algorithm: unknown,
    extractable: boolean,
    keyUsages: string[],
  ): Promise<CryptoKeyLike>;
  verify(
    algorithm: unknown,
    key: CryptoKeyLike,
    signature: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean>;
  digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
}

/** Subset of the WebCrypto `Crypto` interface (globalThis.crypto / node:crypto webcrypto). */
export interface CryptoLike {
  readonly subtle: SubtleCryptoLike;
  getRandomValues<T extends Uint8Array>(array: T): T;
}

export interface AbortSignalLike {
  readonly aborted: boolean;
  readonly reason?: unknown;
  addEventListener(
    type: 'abort',
    listener: () => void,
    options?: { once?: boolean },
  ): void;
  removeEventListener(type: 'abort', listener: () => void): void;
}

export interface FetchResponseLike {
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
}

export interface FetchInitLike {
  method: string;
  headers: Record<string, string>;
  body?: string;
  credentials?: 'include' | 'same-origin' | 'omit';
  signal?: AbortSignalLike;
}

export type FetchLike = (url: string, init: FetchInitLike) => Promise<FetchResponseLike>;

/** `globalThis` viewed as possibly providing `fetch`. */
export interface FetchGlobal {
  fetch?: FetchLike;
}

/** `globalThis` viewed as possibly providing WebCrypto. */
export interface CryptoGlobal {
  crypto?: Partial<CryptoLike>;
}

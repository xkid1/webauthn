import { describe, expect, it } from 'vitest';

import { encodeCbor } from '../cbor/index.js';

import { parseCoseKey } from './key.js';

import type { CborValue } from '@types';

describe('parseCoseKey', () => {
  const x = new Uint8Array(32);
  const key = (entries: [CborValue, CborValue][]) => encodeCbor(new Map(entries));

  it('rejects a curve that does not match alg', () => {
    expect(() =>
      parseCoseKey(
        key([
          [1, 2],
          [3, -7],
          [-1, 2],
          [-2, x],
          [-3, x],
        ]),
      ),
    ).toThrow(/curve/u);
  });

  it('rejects RS1 / unsupported algorithms', () => {
    expect(() =>
      parseCoseKey(
        key([
          [1, 2],
          [3, -65535],
          [-1, 1],
          [-2, x],
          [-3, x],
        ]),
      ),
    ).toThrow(expect.objectContaining({ code: 'UNSUPPORTED_ALGORITHM' }) as Error);
  });

  it('rejects RSA keys below 2048 bits', () => {
    expect(() =>
      parseCoseKey(
        key([
          [1, 3],
          [3, -257],
          [-1, new Uint8Array(128)],
          [-2, Uint8Array.of(1, 0, 1)],
        ]),
      ),
    ).toThrow(/2048/u);
  });

  it('requires alg', () => {
    expect(() =>
      parseCoseKey(
        key([
          [1, 2],
          [-1, 1],
          [-2, x],
          [-3, x],
        ]),
      ),
    ).toThrow(/alg/u);
  });
});

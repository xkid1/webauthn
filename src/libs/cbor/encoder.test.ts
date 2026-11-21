import { describe, expect, it } from 'vitest';

import { decodeCbor } from './decoder';
import { encodeCbor } from './encoder';

import type { CborValue } from '@types';

describe('encodeCbor', () => {
  it('round-trips the WebAuthn data model', () => {
    const value = new Map<CborValue, CborValue>([
      [1, 2],
      [-1, -300],
      ['fmt', 'packed'],
      ['bytes', Uint8Array.of(1, 2, 3)],
      ['arr', [true, false, null, 2 ** 40]],
      ['nested', new Map<CborValue, CborValue>([[3, 'x']])],
    ]);
    expect(decodeCbor(encodeCbor(value))).toEqual(value);
  });

  it('encodes canonical key order (length-first)', () => {
    const encoded = encodeCbor(
      new Map<CborValue, CborValue>([
        ['bb', 1],
        ['a', 2],
        [10, 3],
      ]),
    );
    const keys = [...(decodeCbor(encoded) as Map<CborValue, CborValue>).keys()];
    expect(keys).toEqual([10, 'a', 'bb']);
  });
});

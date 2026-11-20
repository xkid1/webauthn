import { describe, expect, it } from 'vitest';

import { MemoryChallengeStore } from './challenge-store.js';

describe('MemoryChallengeStore', () => {
  it('expires, evicts and hands out each challenge once', () => {
    let now = 1_000;
    const store = new MemoryChallengeStore({ maxEntries: 2, now: () => now });
    store.set('a', 'A', 100);
    store.set('b', 'B', 100);
    store.set('c', 'C', 100);
    expect(store.size).toBe(2);
    expect(store.take('a')).toBeUndefined();
    now += 101;
    expect(store.take('b')).toBeUndefined();
    store.set('d', 'D', 100);
    expect(store.take('d')).toBe('D');
    expect(store.take('d')).toBeUndefined();
    expect(() => new MemoryChallengeStore({ maxEntries: 0 })).toThrow();
  });
});

import { WebAuthnError } from '@utils';

import type {
  Base64URLString,
  ChallengeStore,
  MemoryChallengeStoreOptions,
  StoredChallenge,
} from '@types';

/**
 * In-process, single-use challenge store with TTL. Suitable for development
 * and single-instance deployments. For multiple instances use a shared store
 * (Redis `GETDEL`, a DB row deleted on read, a signed+encrypted session…).
 */
export class MemoryChallengeStore implements ChallengeStore {
  private readonly entries = new Map<string, StoredChallenge>();
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(options: MemoryChallengeStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? 10_000;
    this.now = options.now ?? Date.now;
    if (!Number.isInteger(this.maxEntries) || this.maxEntries < 1) {
      throw new WebAuthnError('INVALID_CONFIG', 'maxEntries must be a positive integer');
    }
  }

  set(key: string, challenge: Base64URLString, ttlMs: number): void {
    if (key.length === 0)
      throw new WebAuthnError('INVALID_INPUT', 'Challenge key must not be empty');
    this.prune();
    this.entries.delete(key);
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    this.entries.set(key, { challenge, expiresAt: this.now() + ttlMs });
  }

  take(key: string): Base64URLString | undefined {
    const entry = this.entries.get(key);
    this.entries.delete(key);
    if (!entry || entry.expiresAt <= this.now()) return undefined;
    return entry.challenge;
  }

  get size(): number {
    return this.entries.size;
  }

  private prune(): void {
    const now = this.now();
    for (const [key, entry] of this.entries)
      if (entry.expiresAt <= now) this.entries.delete(key);
  }
}

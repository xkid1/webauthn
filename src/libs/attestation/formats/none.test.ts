import { describe, expect, it } from 'vitest';

import { attestationContext } from '../../../../tests/index.js';

import { verifyNoneAttestation } from './none.js';

import type { CborValue } from '@types';

describe('none attestation (§8.7)', () => {
  it('accepts an empty statement and reports no trust', async () => {
    await expect(verifyNoneAttestation(await attestationContext({}))).resolves.toEqual({
      type: 'none',
      trustPath: [],
      trusted: false,
    });
  });

  it('rejects a non-empty statement', async () => {
    const ctx = await attestationContext({});
    const attStmt = new Map<CborValue, CborValue>([['sig', new Uint8Array(1)]]);
    await expect(verifyNoneAttestation({ ...ctx, attStmt })).rejects.toMatchObject({
      code: 'ATTESTATION_INVALID',
    });
  });
});

import { describe, expect, it } from 'vitest';

import { attestationContext } from '../../../tests/index.js';

import { BUILT_IN_ATTESTATION_VERIFIERS, verifyAttestationStatement } from './verify.js';

import type { AttestationVerifier } from '@types';

describe('verifyAttestationStatement', () => {
  it('ships a verifier for every WebAuthn L3 format', () => {
    expect(Object.keys(BUILT_IN_ATTESTATION_VERIFIERS).sort()).toEqual([
      'android-key',
      'android-safetynet',
      'apple',
      'fido-u2f',
      'none',
      'packed',
      'tpm',
    ]);
    expect(Object.isFrozen(BUILT_IN_ATTESTATION_VERIFIERS)).toBe(true);
  });

  it('dispatches by fmt, lets custom verifiers override, and rejects unknown formats', async () => {
    const ctx = await attestationContext({});
    await expect(verifyAttestationStatement(ctx)).resolves.toMatchObject({
      type: 'none',
    });

    const custom: AttestationVerifier = () =>
      Promise.resolve({ type: 'basic', trustPath: [], trusted: true });
    await expect(
      verifyAttestationStatement(ctx, { none: custom }),
    ).resolves.toMatchObject({
      trusted: true,
    });

    await expect(
      verifyAttestationStatement({ ...ctx, format: 'vendor-proprietary' }),
    ).rejects.toMatchObject({ code: 'ATTESTATION_FORMAT_UNSUPPORTED' });
    await expect(
      verifyAttestationStatement({ ...ctx, format: '__proto__' }),
    ).rejects.toMatchObject({ code: 'ATTESTATION_FORMAT_UNSUPPORTED' });
  });
});

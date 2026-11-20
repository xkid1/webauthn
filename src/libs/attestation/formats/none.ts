import { WebAuthnError } from '@utils';

import type { AttestationVerifier } from '@types';

/** WebAuthn §8.7 – "none": attStmt must be an empty map. */
export const verifyNoneAttestation: AttestationVerifier = (ctx) => {
  if (ctx.attStmt.size !== 0) {
    return Promise.reject(
      new WebAuthnError('ATTESTATION_INVALID', '"none" attStmt must be empty'),
    );
  }
  return Promise.resolve({ type: 'none', trustPath: [], trusted: false });
};

import { WebAuthnError } from '@utils';

import { verifyAndroidKeyAttestation } from './formats/android-key.js';
import { verifyAndroidSafetyNetAttestation } from './formats/android-safetynet.js';
import { verifyAppleAttestation } from './formats/apple.js';
import { verifyFidoU2fAttestation } from './formats/fido-u2f.js';
import { verifyNoneAttestation } from './formats/none.js';
import { verifyPackedAttestation } from './formats/packed.js';
import { verifyTpmAttestation } from './formats/tpm.js';

import type { AttestationContext, AttestationResult, AttestationVerifier } from '@types';

/** Built-in statement verifiers for every format defined in WebAuthn L3 §8. */
export const BUILT_IN_ATTESTATION_VERIFIERS: Readonly<
  Record<string, AttestationVerifier>
> = Object.freeze({
  'none': verifyNoneAttestation,
  'packed': verifyPackedAttestation,
  'fido-u2f': verifyFidoU2fAttestation,
  'tpm': verifyTpmAttestation,
  'android-key': verifyAndroidKeyAttestation,
  'android-safetynet': verifyAndroidSafetyNetAttestation,
  'apple': verifyAppleAttestation,
});

export async function verifyAttestationStatement(
  context: AttestationContext,
  custom: Readonly<Record<string, AttestationVerifier>> = {},
): Promise<AttestationResult> {
  const verifiers = { ...BUILT_IN_ATTESTATION_VERIFIERS, ...custom };
  const verifier = Object.hasOwn(verifiers, context.format)
    ? verifiers[context.format]
    : undefined;
  if (!verifier) {
    throw new WebAuthnError(
      'ATTESTATION_FORMAT_UNSUPPORTED',
      `Attestation format "${context.format}" is not supported. Register a verifier via config.attestationVerifiers or request attestation "none".`,
    );
  }
  return verifier(context);
}

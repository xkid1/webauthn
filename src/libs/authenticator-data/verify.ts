import { sha256, timingSafeEqual, utf8Encode, WebAuthnError } from '@utils';

import type { CryptoLike, ParsedAuthenticatorData } from '@types';

/** Assert authData.rpIdHash === SHA-256(rpId). */
export async function verifyRpIdHash(
  parsed: ParsedAuthenticatorData,
  rpId: string,
  crypto: CryptoLike,
): Promise<void> {
  const expected = await sha256(utf8Encode(rpId), crypto);
  if (!timingSafeEqual(parsed.rpIdHash, expected)) {
    throw new WebAuthnError(
      'RP_ID_MISMATCH',
      'rpIdHash does not match the configured rpId',
    );
  }
}

/** Enforce user presence (always) and user verification (when required). */
export function verifyUserFlags(
  parsed: ParsedAuthenticatorData,
  requireUserVerification: boolean,
): void {
  if (!parsed.flags.userPresent) {
    throw new WebAuthnError('USER_PRESENCE_REQUIRED', 'User presence flag (UP) not set');
  }
  if (requireUserVerification && !parsed.flags.userVerified) {
    throw new WebAuthnError(
      'USER_VERIFICATION_REQUIRED',
      'User verification flag (UV) not set',
    );
  }
}

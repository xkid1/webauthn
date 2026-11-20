import { randomBytes, toBase64Url, WebAuthnError } from '@utils';

import type { ResolvedRelyingPartyConfig } from '@types';

/** Fresh CSPRNG challenge (or a caller-supplied one of at least 16 bytes), base64url-encoded. */
export function makeChallenge(
  config: ResolvedRelyingPartyConfig,
  supplied?: Uint8Array,
): string {
  if (supplied) {
    if (supplied.length < 16) {
      throw new WebAuthnError('INVALID_INPUT', 'Challenge must be at least 16 bytes');
    }
    return toBase64Url(supplied);
  }
  return toBase64Url(randomBytes(config.challengeSize, config.crypto));
}

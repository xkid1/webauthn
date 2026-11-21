import { readUint16BE, readUint32BE, WebAuthnError } from '@utils';

import { decodeCborFirst, isCborMap } from '../cbor';

import type { AuthenticatorFlags, ParsedAuthenticatorData } from '@types';

/** WebAuthn §6.1 – maximum credential ID length. */
export const MAX_CREDENTIAL_ID_LENGTH = 1023;

const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 } as const;

const fail = (message: string): never => {
  throw new WebAuthnError('INVALID_AUTHENTICATOR_DATA', `authenticatorData: ${message}`);
};

export function parseFlags(raw: number): AuthenticatorFlags {
  return {
    userPresent: (raw & FLAG.UP) !== 0,
    userVerified: (raw & FLAG.UV) !== 0,
    backupEligible: (raw & FLAG.BE) !== 0,
    backedUp: (raw & FLAG.BS) !== 0,
    attestedCredentialData: (raw & FLAG.AT) !== 0,
    extensionData: (raw & FLAG.ED) !== 0,
    raw,
  };
}

/** Parse authenticatorData (WebAuthn §6.1) and reject any malformed or trailing bytes. */
export function parseAuthenticatorData(authData: Uint8Array): ParsedAuthenticatorData {
  if (authData.length < 37) fail('too short');
  const rpIdHash = authData.slice(0, 32);
  const flags = parseFlags(authData[32]!);
  const signCount = readUint32BE(authData, 33);
  let offset = 37;

  if (flags.backedUp && !flags.backupEligible) {
    throw new WebAuthnError(
      'INVALID_FLAGS',
      'Backup state set without backup eligibility',
    );
  }

  let attestedCredentialData: ParsedAuthenticatorData['attestedCredentialData'];
  if (flags.attestedCredentialData) {
    if (authData.length < offset + 18) fail('truncated attested credential data');
    const aaguid = authData.slice(offset, offset + 16);
    const idLength = readUint16BE(authData, offset + 16);
    offset += 18;
    if (idLength === 0) fail('empty credential ID');
    if (idLength > MAX_CREDENTIAL_ID_LENGTH) {
      throw new WebAuthnError(
        'CREDENTIAL_ID_TOO_LONG',
        'Credential ID exceeds 1023 bytes',
      );
    }
    if (authData.length < offset + idLength) fail('truncated credential ID');
    const credentialId = authData.slice(offset, offset + idLength);
    offset += idLength;
    const { value, length } = decodeCborFirst(authData.subarray(offset));
    if (!isCborMap(value)) fail('credential public key is not a COSE map');
    const credentialPublicKey = authData.slice(offset, offset + length);
    offset += length;
    attestedCredentialData = { aaguid, credentialId, credentialPublicKey };
  }

  let extensions: ParsedAuthenticatorData['extensions'];
  if (flags.extensionData) {
    const { value, length } = decodeCborFirst(authData.subarray(offset));
    if (!isCborMap(value)) return fail('extensions are not a CBOR map');
    extensions = value;
    offset += length;
  }

  if (offset !== authData.length) fail('unexpected trailing bytes');

  return {
    rpIdHash,
    flags,
    signCount,
    ...(attestedCredentialData ? { attestedCredentialData } : {}),
    ...(extensions ? { extensions } : {}),
  };
}

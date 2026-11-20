import {
  fromBase64Url,
  isRecord,
  timingSafeEqual,
  utf8Decode,
  WebAuthnError,
} from '@utils';

import type {
  Base64URLString,
  ClientDataExpectations,
  CollectedClientData,
  ParsedClientData,
} from '@types';

/** clientDataJSON is small; anything larger is hostile. */
const MAX_CLIENT_DATA_BYTES = 16 * 1024;

const invalid = (message: string): never => {
  throw new WebAuthnError('INVALID_INPUT', `clientDataJSON: ${message}`);
};

export function parseClientDataJSON(encoded: Base64URLString): ParsedClientData {
  const raw = fromBase64Url(encoded);
  if (raw.length > MAX_CLIENT_DATA_BYTES) invalid('too large');
  let json: unknown;
  try {
    json = JSON.parse(utf8Decode(raw));
  } catch (cause) {
    throw new WebAuthnError('INVALID_INPUT', 'clientDataJSON is not valid JSON', {
      cause,
    });
  }
  if (!isRecord(json)) return invalid('not an object');
  const { type, challenge, origin, crossOrigin, topOrigin } = json;
  if (type !== 'webauthn.create' && type !== 'webauthn.get') invalid('bad "type"');
  if (typeof challenge !== 'string') invalid('missing "challenge"');
  if (typeof origin !== 'string') invalid('missing "origin"');
  if (crossOrigin !== undefined && typeof crossOrigin !== 'boolean')
    invalid('bad "crossOrigin"');
  if (topOrigin !== undefined && typeof topOrigin !== 'string')
    invalid('bad "topOrigin"');

  const data: CollectedClientData = {
    type: type as CollectedClientData['type'],
    challenge: challenge as string,
    origin: origin as string,
    ...(crossOrigin === undefined ? {} : { crossOrigin: crossOrigin as boolean }),
    ...(topOrigin === undefined ? {} : { topOrigin: topOrigin as string }),
  };
  return { raw, data };
}

/** WebAuthn §7.1 steps 7–10 / §7.2 steps 11–14. */
export function verifyClientData(
  data: CollectedClientData,
  expected: ClientDataExpectations,
): void {
  if (data.type !== expected.type) {
    throw new WebAuthnError(
      'TYPE_MISMATCH',
      `Expected client data type "${expected.type}"`,
    );
  }

  let received: Uint8Array;
  try {
    received = fromBase64Url(data.challenge);
  } catch {
    throw new WebAuthnError('CHALLENGE_MISMATCH', 'Challenge mismatch');
  }
  if (!timingSafeEqual(received, fromBase64Url(expected.challenge))) {
    throw new WebAuthnError('CHALLENGE_MISMATCH', 'Challenge mismatch');
  }

  if (!expected.origins.includes(data.origin)) {
    throw new WebAuthnError('ORIGIN_MISMATCH', `Origin "${data.origin}" is not allowed`);
  }

  if (data.crossOrigin === true) {
    if (!expected.allowCrossOrigin) {
      throw new WebAuthnError(
        'CROSS_ORIGIN_NOT_ALLOWED',
        'Cross-origin ceremonies are disabled',
      );
    }
    if (
      data.topOrigin === undefined ||
      !expected.allowedTopOrigins.includes(data.topOrigin)
    ) {
      throw new WebAuthnError('TOP_ORIGIN_MISMATCH', 'topOrigin is not allowed');
    }
  }
}

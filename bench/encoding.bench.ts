import { describe, test } from 'vitest';

import {
  decodeCbor,
  encodeCbor,
  isCborMap,
  parseAuthenticatorData,
  parseClientDataJSON,
  parseCoseKey,
} from '@libs';
import { fromBase64Url, randomBytes, toBase64Url, toBytes } from '@utils';

import { passkeys } from './fixtures.js';

const small = randomBytes(32);
const large = randomBytes(4096);
const smallText = toBase64Url(small);
const largeText = toBase64Url(large);

const [es256, , rs256] = passkeys;
if (!es256 || !rs256) throw new Error('bench fixtures missing');
const attestationObject = fromBase64Url(es256.registration.response.attestationObject);
const decoded = decodeCbor(attestationObject);
const authData = isCborMap(decoded) ? decoded.get('authData') : undefined;
if (!(authData instanceof Uint8Array)) throw new Error('bench fixture: authData missing');
const clientDataJSON = es256.registration.response.clientDataJSON;
const es256Key = toBytes(es256.credential.publicKey);
const rs256Key = toBytes(rs256.credential.publicKey);

describe('encoding', () => {
  test('base64url', async ({ bench }) => {
    await bench.compare(
      bench('encode 32 B', () => {
        toBase64Url(small);
      }),
      bench('decode 32 B', () => {
        fromBase64Url(smallText);
      }),
      bench('encode 4 KiB', () => {
        toBase64Url(large);
      }),
      bench('decode 4 KiB', () => {
        fromBase64Url(largeText);
      }),
    );
  });

  test('parsers', async ({ bench }) => {
    await bench.compare(
      bench('decodeCbor (attestationObject)', () => {
        decodeCbor(attestationObject);
      }),
      bench('encodeCbor (attestationObject)', () => {
        encodeCbor(decoded);
      }),
      bench('parseAuthenticatorData (attested credential)', () => {
        parseAuthenticatorData(authData);
      }),
      bench('parseClientDataJSON', () => {
        parseClientDataJSON(clientDataJSON);
      }),
      bench('parseCoseKey (ES256)', () => {
        parseCoseKey(es256Key);
      }),
      bench('parseCoseKey (RS256)', () => {
        parseCoseKey(rs256Key);
      }),
    );
  });
});

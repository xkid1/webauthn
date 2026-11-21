import { describe, expect, it } from 'vitest';

import { utf8Encode } from '@utils';

import { SoftAuthenticator, testCrypto as crypto } from '../../../tests';
import { COSEAlgorithm } from '../cose';

import { verifyCoseSignature } from './verify';

describe('verifyCoseSignature', () => {
  it.each([COSEAlgorithm.ES256, COSEAlgorithm.EdDSA, COSEAlgorithm.RS256] as const)(
    'verifies alg %i and rejects a tampered signature',
    async (alg) => {
      const auth = await SoftAuthenticator.create(alg);
      const data = utf8Encode('hello webauthn');
      const signature = await auth.sign(data);
      await expect(
        verifyCoseSignature({ crypto, publicKey: auth.cosePublicKey, signature, data }),
      ).resolves.toBeUndefined();
      signature[signature.length - 1]! ^= 1;
      await expect(
        verifyCoseSignature({ crypto, publicKey: auth.cosePublicKey, signature, data }),
      ).rejects.toMatchObject({ code: 'SIGNATURE_INVALID' });
    },
  );
});

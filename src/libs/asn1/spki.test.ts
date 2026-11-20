import { describe, expect, it } from 'vitest';

import {
  type Alg,
  makeCertificate,
  makeTestRoot,
  ROOT_SUBJECT,
  SoftAuthenticator,
} from '../../../tests/index.js';

import { COSEAlgorithm, parseCoseKey } from '../cose/index.js';

import { certificateKeyMatchesCose } from './spki.js';
import { parseCertificate } from './x509.js';

describe('certificateKeyMatchesCose', () => {
  const algs: Alg[] = [COSEAlgorithm.ES256, COSEAlgorithm.RS256, COSEAlgorithm.EdDSA];

  it.each(algs)(
    'matches the certified key for alg %i and rejects any other key',
    async (alg) => {
      const root = await makeTestRoot();
      const auth = await SoftAuthenticator.create(alg);
      const other = await SoftAuthenticator.create(alg);
      const cert = parseCertificate(
        (
          await makeCertificate({
            subject: ROOT_SUBJECT,
            issuer: root,
            keyPair: auth.keyPair,
          })
        ).der,
      );
      expect(certificateKeyMatchesCose(cert, parseCoseKey(auth.cosePublicKey))).toBe(
        true,
      );
      expect(certificateKeyMatchesCose(cert, parseCoseKey(other.cosePublicKey))).toBe(
        false,
      );
      for (const foreign of algs.filter((a) => a !== alg)) {
        const f = await SoftAuthenticator.create(foreign);
        expect(certificateKeyMatchesCose(cert, parseCoseKey(f.cosePublicKey))).toBe(
          false,
        );
      }
    },
  );
});

/**
 * Shared, pre-generated ceremony data for benchmarks. Everything expensive
 * (key generation, signing, certificate minting) happens once at import time
 * so each bench measures verification only.
 */
import {
  createAndroidSafetyNetVerifier,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  resolveConfig,
  verifyRegistrationResponse,
} from '@apps';
import { COSEAlgorithm } from '@libs';

import {
  type Alg,
  androidKeyAttestation,
  appleAttestation,
  ATTESTATION_SUBJECT,
  makeCertificate,
  ORIGIN,
  type RegisterOverrides,
  ROOT_SUBJECT,
  RP_ID,
  safetyNetAttestation,
  SoftAuthenticator,
  tpmAttestation,
} from '../tests';

import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  RelyingPartyConfig,
  ResolvedRelyingPartyConfig,
  StoredCredential,
} from '@types';

export const user = { name: 'bench@example.com', displayName: 'Bench' };
const base: RelyingPartyConfig = { rpId: RP_ID, rpName: 'Bench', origins: [ORIGIN] };
export const config: ResolvedRelyingPartyConfig = resolveConfig(base);

export interface Ceremony {
  readonly label: string;
  readonly config: ResolvedRelyingPartyConfig;
  readonly registration: RegistrationResponseJSON;
  readonly registrationChallenge: string;
  readonly authentication: AuthenticationResponseJSON;
  readonly authenticationChallenge: string;
  readonly credential: StoredCredential;
}

async function ceremony(
  label: string,
  alg: Alg,
  cfg: ResolvedRelyingPartyConfig = config,
  overrides: RegisterOverrides = {},
): Promise<Ceremony> {
  const auth = await SoftAuthenticator.create(alg);
  const regOptions = generateRegistrationOptions(cfg, { user });
  const registration = await auth.register(regOptions, overrides);
  const { credential } = await verifyRegistrationResponse(cfg, {
    response: registration,
    expectedChallenge: regOptions.challenge,
  });
  const authOptions = generateAuthenticationOptions(cfg);
  // signCount 1 > stored counter 0, so the same assertion verifies on every iteration.
  const authentication = await auth.authenticate(authOptions, { signCount: 1 });
  return {
    label,
    config: cfg,
    registration,
    registrationChallenge: regOptions.challenge,
    authentication,
    authenticationChallenge: authOptions.challenge,
    credential: { id: credential.id, publicKey: credential.publicKey, counter: 0 },
  };
}

export const passkeys: readonly Ceremony[] = await Promise.all([
  ceremony('ES256', COSEAlgorithm.ES256),
  ceremony('EdDSA', COSEAlgorithm.EdDSA),
  ceremony('RS256', COSEAlgorithm.RS256),
]);

const root = await makeCertificate({ subject: ROOT_SUBJECT, ca: true });
const leaf = await makeCertificate({
  subject: ATTESTATION_SUBJECT,
  issuer: root,
  serial: 2,
});
const anchored = resolveConfig({
  ...base,
  attestation: 'direct',
  trustAnchors: [root.der],
  // Pre-generated SafetyNet responses must stay "fresh" for the whole bench run. The
  // timestamp is fixed at import time, so a backwards wall-clock step (NTP or WSL2 time
  // resync) would otherwise make it look "in the future". Bench-only tolerance; the
  // library default (clockSkewMs: 0) is unchanged.
  attestationVerifiers: {
    'android-safetynet': createAndroidSafetyNetVerifier({
      maxAgeMs: 3_600_000,
      clockSkewMs: 60_000,
    }),
  },
});

export const attestations: readonly Ceremony[] = await Promise.all([
  ceremony('none', COSEAlgorithm.ES256, anchored),
  ceremony('packed (self)', COSEAlgorithm.ES256, anchored, { format: 'packed-self' }),
  ceremony('packed (x5c)', COSEAlgorithm.ES256, anchored, {
    format: 'packed-x5c',
    attestationChain: [leaf],
  }),
  ceremony('fido-u2f', COSEAlgorithm.ES256, anchored, {
    format: 'fido-u2f',
    attestationChain: [leaf],
  }),
  ceremony('tpm', COSEAlgorithm.ES256, anchored, { attest: tpmAttestation(root) }),
  ceremony('android-key', COSEAlgorithm.ES256, anchored, {
    attest: androidKeyAttestation(root),
  }),
  ceremony('android-safetynet', COSEAlgorithm.ES256, anchored, {
    attest: safetyNetAttestation(root),
  }),
  ceremony('apple', COSEAlgorithm.ES256, anchored, { attest: appleAttestation(root) }),
]);

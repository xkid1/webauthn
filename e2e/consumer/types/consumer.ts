/**
 * Type-level end-to-end test: a TypeScript application using the published
 * declarations. It is only compiled (never run), with strict settings,
 * `skipLibCheck: false` and NO DOM or Node lib types, proving the package's
 * types are complete, self-contained and runtime-agnostic.
 */
import { COSEAlgorithm, decodeCbor } from '@xkid1/webauthn';
import {
  createAndroidPasskeyClient,
  type AndroidCredentialBridge,
  type AndroidPasskeyClient,
} from '@xkid1/webauthn/android';
import {
  createWebAuthnClient,
  isWebAuthnSupported,
  startRegistration,
  type RegistrationResponseJSON,
  type WebAuthnClient,
} from '@xkid1/webauthn/client';
import {
  createAndroidKeyVerifier,
  createWebAuthnServer,
  getErrorHint,
  isWebAuthnError,
  MemoryChallengeStore,
  type AttestationVerifier,
  type ChallengeStore,
  type StoredCredential,
  type VerifiedAuthentication,
  type VerifiedRegistration,
  type WebAuthnErrorCode,
  type WebAuthnErrorJSON,
  type WebAuthnServer,
} from '@xkid1/webauthn/server';

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
const assertType = <T extends true>(): T => true as T;

/* ------------------------------- server ------------------------------- */

class RedisLikeStore implements ChallengeStore {
  readonly #data = new Map<string, string>();
  set(key: string, challenge: string): void {
    this.#data.set(key, challenge);
  }
  take(key: string): string | undefined {
    const value = this.#data.get(key);
    this.#data.delete(key);
    return value;
  }
}

const vendorVerifier: AttestationVerifier = (ctx) =>
  Promise.resolve({ type: 'basic', trustPath: [], trusted: ctx.trustAnchors.length > 0 });

export const server: WebAuthnServer = createWebAuthnServer({
  rpId: 'example.com',
  rpName: 'Example',
  origins: ['https://example.com'],
  challengeStore: new MemoryChallengeStore(),
  supportedAlgorithms: [COSEAlgorithm.ES256, COSEAlgorithm.EdDSA],
  attestation: 'direct',
  attestationVerifiers: {
    'android-key': createAndroidKeyVerifier({ requireTeeEnforced: true }),
    'vendor-fmt': vendorVerifier,
  },
});

export const redisServer = createWebAuthnServer({
  rpId: 'example.com',
  rpName: 'Example',
  origins: ['https://example.com'],
  challengeStore: new RedisLikeStore(),
});

// @ts-expect-error rpName and origins are required
createWebAuthnServer({ rpId: 'example.com' });

export async function registerFlow(
  response: RegistrationResponseJSON,
): Promise<StoredCredential> {
  const options = await server.generateRegistrationOptions({
    user: { name: 'alice' },
    sessionKey: 's1',
  });
  const challenge: string = options.challenge;
  void challenge;

  const result: VerifiedRegistration = await server.verifyRegistration({
    response,
    sessionKey: 's1',
  });
  const { id, publicKey, counter, transports } = result.credential;
  return { id, publicKey, counter, ...(transports ? { transports } : {}) };
}

export async function signInFlow(stored: StoredCredential): Promise<number> {
  const options = await server.generateAuthenticationOptions({ sessionKey: 's2' });
  void options;
  const result: VerifiedAuthentication = await server.verifyAuthentication({
    response: {} as never,
    sessionKey: 's2',
    credential: stored,
  });
  return result.newCounter;
}

/* ------------------------------- errors ------------------------------- */

export function handle(error: unknown): WebAuthnErrorJSON | undefined {
  if (isWebAuthnError(error, 'CHALLENGE_NOT_FOUND', 'CHALLENGE_MISMATCH')) {
    assertType<Equal<typeof error.code, 'CHALLENGE_NOT_FOUND' | 'CHALLENGE_MISMATCH'>>();
    return undefined;
  }
  if (isWebAuthnError(error)) {
    const code: WebAuthnErrorCode = error.code;
    const hint: string = error.hint;
    void [code, hint, getErrorHint(code)];
    return error.toJSON();
  }
  return undefined;
}

// @ts-expect-error unknown error codes are rejected at compile time
isWebAuthnError(new Error(), 'NOT_A_REAL_CODE');

/* ------------------------------- client ------------------------------- */

export const client: WebAuthnClient = createWebAuthnClient({
  baseUrl: 'https://api.example.com',
  headers: async () => ({ 'X-CSRF-Token': 'token' }),
  credentials: 'include',
});

export async function browserFlow(): Promise<RegistrationResponseJSON | undefined> {
  if (!isWebAuthnSupported()) return undefined;
  const optionsJSON = await server.generateRegistrationOptions({ user: { name: 'bob' } });
  return startRegistration({ optionsJSON });
}

/* ------------------------------- android ------------------------------ */

const bridge: AndroidCredentialBridge = {
  createCredential: (requestJson: string) => Promise.resolve(requestJson),
  getCredential: (requestJson: string) =>
    Promise.resolve(JSON.parse(requestJson) as object),
};
export const android: AndroidPasskeyClient = createAndroidPasskeyClient(bridge);

/* -------------------------------- libs -------------------------------- */

export const decoded: unknown = decodeCbor(new Uint8Array([0xa0]));

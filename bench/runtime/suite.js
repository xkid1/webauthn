/**
 * The cross-runtime speed suite. Pure ESM + WebCrypto: the same code runs in
 * Node, Bun, Deno and browsers against the BUILT package (dist/), i.e. exactly
 * what users execute.
 */
import { ALG, SoftAuthenticator } from './authenticator.js';
import { measure } from './harness.js';

const ORIGIN = 'https://example.com';

/**
 * @typedef {import('./harness.js').BenchResult} BenchResult
 * @typedef {{ name: string, reason: string }} Skipped
 */

/**
 * @param {Record<string, any>} webauthn  the module namespace of `@xkid1/webauthn` (dist/index.js)
 * @param {{ timeMs?: number, filter?: RegExp, log?: (line: string) => void }} [options]
 * @returns {Promise<{ results: BenchResult[], skipped: Skipped[] }>}
 */
export async function runSuite(webauthn, { timeMs = 1000, filter, log = () => {} } = {}) {
  const {
    resolveConfig,
    generateRegistrationOptions,
    generateAuthenticationOptions,
    verifyRegistrationResponse,
    verifyAuthenticationResponse,
    toBase64Url,
    fromBase64Url,
    decodeCbor,
  } = webauthn;

  const config = resolveConfig({
    rpId: 'example.com',
    rpName: 'Bench',
    origins: [ORIGIN],
  });
  const user = { name: 'bench@example.com', displayName: 'Bench' };

  /** @type {BenchResult[]} */
  const results = [];
  /** @type {Skipped[]} */
  const skipped = [];

  /** @param {string} name @param {() => unknown} fn */
  async function bench(name, fn) {
    if (filter && !filter.test(name)) return;
    const result = await measure(name, fn, {
      timeMs,
      warmupMs: Math.min(200, timeMs / 2),
    });
    results.push(result);
    log(`${name}: ${Math.round(result.hz).toLocaleString('en-US')} ops/s`);
  }

  // ---- encoding -----------------------------------------------------------
  const kib = globalThis.crypto.getRandomValues(new Uint8Array(1024));
  const kibText = toBase64Url(kib);
  await bench('base64url encode 1 KiB', () => toBase64Url(kib));
  await bench('base64url decode 1 KiB', () => fromBase64Url(kibText));

  // ---- options ------------------------------------------------------------
  await bench('generateRegistrationOptions', () =>
    generateRegistrationOptions(config, { user }),
  );
  await bench('generateAuthenticationOptions', () =>
    generateAuthenticationOptions(config),
  );

  // ---- ceremonies per algorithm -------------------------------------------
  for (const [label, alg] of Object.entries(ALG)) {
    let authenticator;
    try {
      authenticator = await SoftAuthenticator.create(alg);
    } catch (error) {
      skipped.push({
        name: label,
        reason: `WebCrypto cannot generate ${label} keys here (${String(error)})`,
      });
      continue;
    }

    const regOptions = generateRegistrationOptions(config, { user });
    const registration = await authenticator.register(regOptions, ORIGIN);
    const { credential } = await verifyRegistrationResponse(config, {
      response: registration,
      expectedChallenge: regOptions.challenge,
    });
    const attestationObject = fromBase64Url(registration.response.attestationObject);

    const authOptions = generateAuthenticationOptions(config);
    const assertion = await authenticator.authenticate(authOptions, ORIGIN);
    const stored = { id: credential.id, publicKey: credential.publicKey, counter: 0 };

    if (label === 'ES256')
      await bench('decodeCbor attestationObject', () => decodeCbor(attestationObject));
    await bench(`verifyRegistrationResponse ${label}`, () =>
      verifyRegistrationResponse(config, {
        response: registration,
        expectedChallenge: regOptions.challenge,
      }),
    );
    await bench(`verifyAuthenticationResponse ${label}`, () =>
      verifyAuthenticationResponse(config, {
        response: assertion,
        expectedChallenge: authOptions.challenge,
        credential: stored,
      }),
    );
  }

  return { results, skipped };
}

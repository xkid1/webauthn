/**
 * A software passkey authenticator for end-to-end tests, written the way an
 * application developer would: plain Node.js, `node:crypto`, and its own tiny
 * CBOR encoder. It deliberately does NOT reuse any encoder from the library
 * under test, so the library can't "agree with itself" on a broken encoding.
 */
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

export const ALG = { ES256: -7, EdDSA: -8, RS256: -257 };

const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const fromB64url = (text) => new Uint8Array(Buffer.from(text, 'base64url'));
const sha256 = (data) => new Uint8Array(createHash('sha256').update(data).digest());
const concat = (...parts) =>
  new Uint8Array(Buffer.concat(parts.map((p) => Buffer.from(p))));

/* ---------------- minimal canonical CBOR encoder (RFC 8949) ---------------- */

function head(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
  return Uint8Array.of(
    (major << 5) | 26,
    n >>> 24,
    (n >> 16) & 0xff,
    (n >> 8) & 0xff,
    n & 0xff,
  );
}

export function cbor(value) {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    return concat(head(3, bytes.length), bytes);
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(cbor));
  if (value instanceof Map) {
    const parts = [head(5, value.size)];
    for (const [k, v] of value) parts.push(cbor(k), cbor(v));
    return concat(...parts);
  }
  throw new TypeError(`cbor: unsupported value ${String(value)}`);
}

/* ---------------------------- authenticator ---------------------------- */

const FLAG = { UP: 0x01, UV: 0x04, AT: 0x40 };

function generate(alg) {
  if (alg === ALG.ES256) return generateKeyPairSync('ec', { namedCurve: 'P-256' });
  if (alg === ALG.EdDSA) return generateKeyPairSync('ed25519');
  if (alg === ALG.RS256) return generateKeyPairSync('rsa', { modulusLength: 2048 });
  throw new Error(`unsupported alg ${alg}`);
}

function coseKey(alg, publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  if (alg === ALG.ES256) {
    return new Map([
      [1, 2],
      [3, alg],
      [-1, 1],
      [-2, fromB64url(jwk.x)],
      [-3, fromB64url(jwk.y)],
    ]);
  }
  if (alg === ALG.EdDSA)
    return new Map([
      [1, 1],
      [3, alg],
      [-1, 6],
      [-2, fromB64url(jwk.x)],
    ]);
  return new Map([
    [1, 3],
    [3, alg],
    [-1, fromB64url(jwk.n)],
    [-2, fromB64url(jwk.e)],
  ]);
}

export class SoftAuthenticator {
  /** @param {number} alg COSE algorithm */
  constructor(alg = ALG.ES256) {
    this.alg = alg;
    this.keys = generate(alg);
    this.credentialId = new Uint8Array(randomBytes(32));
    this.counter = 0;
    this.userHandle = undefined;
  }

  get id() {
    return b64url(this.credentialId);
  }

  #sign(data) {
    const hash = this.alg === ALG.EdDSA ? null : 'sha256';
    return new Uint8Array(sign(hash, data, this.keys.privateKey)); // ECDSA: DER, as authenticators emit
  }

  #authData(rpId, flags, extra = new Uint8Array(0)) {
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, this.counter);
    return concat(sha256(rpId), Uint8Array.of(flags), counter, extra);
  }

  /**
   * navigator.credentials.create() equivalent, returning RegistrationResponseJSON.
   * @param {object} options PublicKeyCredentialCreationOptionsJSON
   * @param {{ origin: string }} context
   */
  register(options, { origin }) {
    this.userHandle = options.user.id;
    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: options.challenge,
        origin,
        crossOrigin: false,
      }),
    );
    const idLength = Uint8Array.of(
      this.credentialId.length >> 8,
      this.credentialId.length & 0xff,
    );
    const attested = concat(
      new Uint8Array(16),
      idLength,
      this.credentialId,
      cbor(coseKey(this.alg, this.keys.publicKey)),
    );
    const authData = this.#authData(options.rp.id, FLAG.UP | FLAG.UV | FLAG.AT, attested);
    const attestationObject = cbor(
      new Map([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: {
        clientDataJSON: b64url(clientDataJSON),
        attestationObject: b64url(attestationObject),
        transports: ['internal', 'hybrid'],
        publicKeyAlgorithm: this.alg,
      },
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
    };
  }

  /**
   * navigator.credentials.get() equivalent, returning AuthenticationResponseJSON.
   * @param {object} options PublicKeyCredentialRequestOptionsJSON
   * @param {{ origin: string }} context
   */
  authenticate(options, { origin }) {
    this.counter += 1;
    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: options.challenge,
        origin,
        crossOrigin: false,
      }),
    );
    const authData = this.#authData(options.rpId, FLAG.UP | FLAG.UV);
    const signature = this.#sign(concat(authData, sha256(clientDataJSON)));
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
        userHandle: this.userHandle,
      },
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
    };
  }
}

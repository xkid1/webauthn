/**
 * Runtime-agnostic software authenticator for the cross-runtime benchmark.
 * Uses only WebCrypto + standard JS (no Buffer, no node:*), so the same file
 * runs in Node, Bun, Deno and browsers. It has its own CBOR / base64url
 * encoders so the library under test never verifies its own encodings.
 */

export const ALG = /** @type {const} */ ({ ES256: -7, EdDSA: -8, RS256: -257 });

const subtle = globalThis.crypto.subtle;

/** @typedef {{ publicKey: CryptoKey, privateKey: CryptoKey }} KeyPair */
/** @typedef {Map<number, number | Uint8Array>} CoseKey */
const encoder = new TextEncoder();

/** @param {Uint8Array} bytes */
export function b64url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

/** @param {string} text */
export function fromB64url(text) {
  const padded = text.replace(/-/gu, '+').replace(/_/gu, '/');
  return Uint8Array.from(atob(padded + '='.repeat((4 - (padded.length % 4)) % 4)), (c) =>
    c.charCodeAt(0),
  );
}

/** @param {...Uint8Array} parts @returns {Uint8Array<ArrayBuffer>} */
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** @param {Uint8Array<ArrayBuffer>} data */
async function sha256(data) {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

/** @param {number} major @param {number} n */
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

/** Minimal CBOR encoder (ints, text, bytes, arrays, Maps). @param {unknown} value @returns {Uint8Array} */
export function cbor(value) {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const bytes = encoder.encode(value);
    return concat(head(3, bytes.length), bytes);
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(cbor));
  if (value instanceof Map) {
    /** @type {Uint8Array[]} */
    const parts = [head(5, value.size)];
    for (const [k, v] of value) parts.push(cbor(k), cbor(v));
    return concat(...parts);
  }
  throw new TypeError('cbor: unsupported value');
}

/** IEEE P1363 (r||s) → ASN.1 DER, as real authenticators emit ECDSA. @param {Uint8Array} raw */
function rawToDer(raw) {
  /** @param {Uint8Array} v */
  const int = (v) => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i += 1;
    let body = v.subarray(i);
    if ((body[0] ?? 0) & 0x80) body = concat(Uint8Array.of(0), body);
    return concat(Uint8Array.of(0x02, body.length), body);
  };
  const half = raw.length / 2;
  const seq = concat(int(raw.subarray(0, half)), int(raw.subarray(half)));
  return concat(Uint8Array.of(0x30, seq.length), seq);
}

/** @param {number} alg */
function keyParams(alg) {
  if (alg === ALG.ES256)
    return {
      gen: { name: 'ECDSA', namedCurve: 'P-256' },
      sign: { name: 'ECDSA', hash: 'SHA-256' },
    };
  if (alg === ALG.EdDSA) return { gen: { name: 'Ed25519' }, sign: { name: 'Ed25519' } };
  return {
    gen: {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: Uint8Array.of(1, 0, 1),
      hash: 'SHA-256',
    },
    sign: { name: 'RSASSA-PKCS1-v1_5' },
  };
}

export class SoftAuthenticator {
  /**
   * @param {number} alg
   * @param {KeyPair} keys
   * @param {Uint8Array} coseKey
   */
  constructor(alg, keys, coseKey) {
    this.alg = alg;
    this.keys = keys;
    this.coseKey = coseKey;
    this.credentialId = globalThis.crypto.getRandomValues(new Uint8Array(32));
    this.counter = 0;
    /** @type {string | undefined} */
    this.userHandle = undefined;
  }

  /** @param {number} alg */
  static async create(alg) {
    const params = keyParams(alg);
    const keys = /** @type {KeyPair} */ (
      await subtle.generateKey(params.gen, true, ['sign', 'verify'])
    );
    const jwk = await subtle.exportKey('jwk', keys.publicKey);
    /** @param {string | undefined} v */
    const b = (v) => fromB64url(v ?? '');
    /** @param {[number, number | Uint8Array][]} entries @returns {CoseKey} */
    const coseKey = (entries) => new Map(entries);
    /** @type {CoseKey} */
    let cose;
    if (alg === ALG.ES256) {
      cose = coseKey([
        [1, 2],
        [3, alg],
        [-1, 1],
        [-2, b(jwk.x)],
        [-3, b(jwk.y)],
      ]);
    } else if (alg === ALG.EdDSA) {
      cose = coseKey([
        [1, 1],
        [3, alg],
        [-1, 6],
        [-2, b(jwk.x)],
      ]);
    } else {
      cose = coseKey([
        [1, 3],
        [3, alg],
        [-1, b(jwk.n)],
        [-2, b(jwk.e)],
      ]);
    }
    return new SoftAuthenticator(alg, keys, cbor(cose));
  }

  /** @param {Uint8Array<ArrayBuffer>} data */
  async sign(data) {
    const sig = new Uint8Array(
      await subtle.sign(keyParams(this.alg).sign, this.keys.privateKey, data),
    );
    return this.alg === ALG.ES256 ? rawToDer(sig) : sig;
  }

  /** @param {string} rpId @param {number} flags @param {Uint8Array} [extra] */
  async authData(rpId, flags, extra = new Uint8Array(0)) {
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, this.counter);
    return concat(
      await sha256(encoder.encode(rpId)),
      Uint8Array.of(flags),
      counter,
      extra,
    );
  }

  /**
   * @param {{ challenge: string, rp: { id?: string }, user: { id: string } }} options
   * @param {string} origin
   */
  async register(options, origin) {
    this.userHandle = options.user.id;
    const clientDataJSON = encoder.encode(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: options.challenge,
        origin,
        crossOrigin: false,
      }),
    );
    const id = this.credentialId;
    const attested = concat(
      new Uint8Array(16),
      Uint8Array.of(id.length >> 8, id.length & 0xff),
      id,
      this.coseKey,
    );
    const authData = await this.authData(options.rp.id ?? '', 0x45, attested); // UP | UV | AT
    const attestationObject = cbor(
      new Map(
        /** @type {[string, unknown][]} */ ([
          ['fmt', 'none'],
          ['attStmt', new Map()],
          ['authData', authData],
        ]),
      ),
    );
    return {
      id: b64url(id),
      rawId: b64url(id),
      type: /** @type {const} */ ('public-key'),
      response: {
        clientDataJSON: b64url(clientDataJSON),
        attestationObject: b64url(attestationObject),
        transports: /** @type {const} */ (['internal']),
        publicKeyAlgorithm: this.alg,
      },
      clientExtensionResults: {},
    };
  }

  /**
   * @param {{ challenge: string, rpId?: string }} options
   * @param {string} origin
   */
  async authenticate(options, origin) {
    this.counter += 1;
    const clientDataJSON = encoder.encode(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: options.challenge,
        origin,
        crossOrigin: false,
      }),
    );
    const authData = await this.authData(options.rpId ?? '', 0x05); // UP | UV
    const signature = await this.sign(concat(authData, await sha256(clientDataJSON)));
    return {
      id: b64url(this.credentialId),
      rawId: b64url(this.credentialId),
      type: /** @type {const} */ ('public-key'),
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
        ...(this.userHandle ? { userHandle: this.userHandle } : {}),
      },
      clientExtensionResults: {},
    };
  }
}

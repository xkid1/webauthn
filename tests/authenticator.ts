/**
 * Software authenticator: produces spec-conformant registration and assertion
 * responses so the server can be tested end-to-end without hardware.
 */
import { webcrypto } from 'node:crypto';

import { COSEAlgorithm, encodeCbor, rawToDerSignature } from '@libs';
import { concatBytes, copyBytes, fromBase64Url, toBase64Url, utf8Encode } from '@utils';

import type { TestCertificate } from './der.js';
import type {
  AuthenticationResponseJSON,
  CborValue,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@types';

type CryptoKeyPair = webcrypto.CryptoKeyPair;
type CryptoKey = webcrypto.CryptoKey;

export const RP_ID = 'example.com';
export const ORIGIN = 'https://example.com';

export const FLAGS = {
  UP: 0x01,
  UV: 0x04,
  BE: 0x08,
  BS: 0x10,
  AT: 0x40,
  ED: 0x80,
} as const;

export type Alg =
  typeof COSEAlgorithm.ES256 | typeof COSEAlgorithm.EdDSA | typeof COSEAlgorithm.RS256;

const sha256 = async (data: Uint8Array) =>
  new Uint8Array(await webcrypto.subtle.digest('SHA-256', copyBytes(data)));

export interface ClientDataOverrides {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
  topOrigin?: string;
}

export interface RegisterOverrides extends ClientDataOverrides {
  rpId?: string;
  flags?: number;
  format?: 'none' | 'packed-self' | 'packed-x5c' | 'fido-u2f';
  attestationChain?: readonly TestCertificate[];
  aaguid?: Uint8Array;
  signCount?: number;
  /** Tamper with the self/x5c signature. */
  corruptSignature?: boolean;
  transports?: string[];
  credProps?: boolean;
  /** Build a custom attestation statement (overrides `format`). */
  attest?: (input: {
    authData: Uint8Array;
    clientDataHash: Uint8Array;
    authenticator: SoftAuthenticator;
  }) => Promise<{ fmt: string; attStmt: Map<CborValue, CborValue> }>;
}

export interface AuthenticateOverrides extends ClientDataOverrides {
  rpId?: string;
  flags?: number;
  signCount?: number;
  userHandle?: string | null;
  corruptSignature?: boolean;
}

export class SoftAuthenticator {
  readonly credentialId: Uint8Array;
  signCount = 0;
  userHandle?: string;

  private constructor(
    readonly alg: Alg,
    readonly keyPair: CryptoKeyPair,
    readonly cosePublicKey: Uint8Array,
  ) {
    this.credentialId = webcrypto.getRandomValues(new Uint8Array(32));
  }

  static async create(alg: Alg = COSEAlgorithm.ES256): Promise<SoftAuthenticator> {
    let params:
      webcrypto.RsaHashedKeyGenParams | webcrypto.EcKeyGenParams | { name: 'Ed25519' };
    if (alg === COSEAlgorithm.ES256) params = { name: 'ECDSA', namedCurve: 'P-256' };
    else if (alg === COSEAlgorithm.EdDSA) params = { name: 'Ed25519' };
    else
      params = {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      };
    const keyPair = (await webcrypto.subtle.generateKey(params, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
    const b = (v?: string) => fromBase64Url(v!);
    let cose: Map<CborValue, CborValue>;
    if (alg === COSEAlgorithm.ES256)
      cose = new Map<CborValue, CborValue>([
        [1, 2],
        [3, alg],
        [-1, 1],
        [-2, b(jwk.x)],
        [-3, b(jwk.y)],
      ]);
    else if (alg === COSEAlgorithm.EdDSA)
      cose = new Map<CborValue, CborValue>([
        [1, 1],
        [3, alg],
        [-1, 6],
        [-2, b(jwk.x)],
      ]);
    else
      cose = new Map<CborValue, CborValue>([
        [1, 3],
        [3, alg],
        [-1, b(jwk.n)],
        [-2, b(jwk.e)],
      ]);
    return new SoftAuthenticator(alg, keyPair, encodeCbor(cose));
  }

  get id(): string {
    return toBase64Url(this.credentialId);
  }

  async sign(
    data: Uint8Array,
    key: CryptoKey = this.keyPair.privateKey,
    alg: Alg = this.alg,
  ): Promise<Uint8Array> {
    if (alg === COSEAlgorithm.ES256) {
      const raw = new Uint8Array(
        await webcrypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          key,
          copyBytes(data),
        ),
      );
      return rawToDerSignature(raw);
    }
    const name = alg === COSEAlgorithm.EdDSA ? 'Ed25519' : 'RSASSA-PKCS1-v1_5';
    return new Uint8Array(await webcrypto.subtle.sign({ name }, key, copyBytes(data)));
  }

  private clientData(
    defaults: { type: string; challenge: string },
    o: ClientDataOverrides,
  ): Uint8Array {
    const data: Record<string, unknown> = {
      type: o.type ?? defaults.type,
      challenge: o.challenge ?? defaults.challenge,
      origin: o.origin ?? ORIGIN,
      crossOrigin: o.crossOrigin ?? false,
    };
    if (o.topOrigin) data.topOrigin = o.topOrigin;
    return utf8Encode(JSON.stringify(data));
  }

  private async authDataHeader(
    rpId: string,
    flags: number,
    signCount: number,
  ): Promise<Uint8Array> {
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, signCount);
    return concatBytes(await sha256(utf8Encode(rpId)), Uint8Array.of(flags), counter);
  }

  async register(
    options: PublicKeyCredentialCreationOptionsJSON,
    o: RegisterOverrides = {},
  ): Promise<RegistrationResponseJSON> {
    this.userHandle = options.user.id;
    const clientDataJSON = this.clientData(
      { type: 'webauthn.create', challenge: options.challenge },
      o,
    );
    const aaguid = o.aaguid ?? new Uint8Array(16);
    const idLen = Uint8Array.of(
      this.credentialId.length >> 8,
      this.credentialId.length & 0xff,
    );
    const flags = o.flags ?? FLAGS.UP | FLAGS.UV | FLAGS.AT;
    const authData = concatBytes(
      await this.authDataHeader(o.rpId ?? RP_ID, flags, o.signCount ?? 0),
      ...(flags & FLAGS.AT ? [aaguid, idLen, this.credentialId, this.cosePublicKey] : []),
    );
    const clientDataHash = await sha256(clientDataJSON);
    const format = o.format ?? 'none';
    let fmt = 'none';
    let attStmt = new Map<CborValue, CborValue>();

    const maybeCorrupt = (sig: Uint8Array): Uint8Array => {
      if (!o.corruptSignature) return sig;
      const corrupted = sig.slice();
      corrupted[corrupted.length - 1]! ^= 0x01;
      return corrupted;
    };

    if (format === 'packed-self') {
      fmt = 'packed';
      const sig = maybeCorrupt(await this.sign(concatBytes(authData, clientDataHash)));
      attStmt = new Map<CborValue, CborValue>([
        ['alg', this.alg],
        ['sig', sig],
      ]);
    } else if (format === 'packed-x5c') {
      fmt = 'packed';
      const chain = o.attestationChain!;
      const sig = maybeCorrupt(
        await this.sign(
          concatBytes(authData, clientDataHash),
          chain[0]!.keyPair.privateKey,
          COSEAlgorithm.ES256,
        ),
      );
      attStmt = new Map<CborValue, CborValue>([
        ['alg', COSEAlgorithm.ES256],
        ['sig', sig],
        ['x5c', chain.map((c) => c.der)],
      ]);
    } else if (format === 'fido-u2f') {
      fmt = 'fido-u2f';
      const chain = o.attestationChain!;
      const jwk = await webcrypto.subtle.exportKey('jwk', this.keyPair.publicKey);
      const pk = concatBytes(
        Uint8Array.of(4),
        fromBase64Url(jwk.x!),
        fromBase64Url(jwk.y!),
      );
      const data = concatBytes(
        Uint8Array.of(0),
        authData.subarray(0, 32),
        clientDataHash,
        this.credentialId,
        pk,
      );
      const sig = maybeCorrupt(
        await this.sign(data, chain[0]!.keyPair.privateKey, COSEAlgorithm.ES256),
      );
      attStmt = new Map<CborValue, CborValue>([
        ['sig', sig],
        ['x5c', [chain[0]!.der]],
      ]);
    }

    if (o.attest) {
      ({ fmt, attStmt } = await o.attest({
        authData,
        clientDataHash,
        authenticator: this,
      }));
    }

    const attestationObject = encodeCbor(
      new Map<CborValue, CborValue>([
        ['fmt', fmt],
        ['attStmt', attStmt],
        ['authData', authData],
      ]),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: {
        clientDataJSON: toBase64Url(clientDataJSON),
        attestationObject: toBase64Url(attestationObject),
        transports: (o.transports ?? ['internal', 'hybrid']) as never,
        publicKeyAlgorithm: this.alg,
      },
      authenticatorAttachment: 'platform',
      clientExtensionResults:
        o.credProps === undefined ? {} : { credProps: { rk: o.credProps } },
    };
  }

  async authenticate(
    options: PublicKeyCredentialRequestOptionsJSON,
    o: AuthenticateOverrides = {},
  ): Promise<AuthenticationResponseJSON> {
    this.signCount = o.signCount ?? this.signCount + 1;
    const clientDataJSON = this.clientData(
      { type: 'webauthn.get', challenge: options.challenge },
      o,
    );
    const authData = await this.authDataHeader(
      o.rpId ?? RP_ID,
      o.flags ?? FLAGS.UP | FLAGS.UV,
      this.signCount,
    );
    const sig = await this.sign(concatBytes(authData, await sha256(clientDataJSON)));
    if (o.corruptSignature) sig[sig.length - 1]! ^= 0x01;
    const userHandle = o.userHandle === undefined ? this.userHandle : o.userHandle;
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: {
        clientDataJSON: toBase64Url(clientDataJSON),
        authenticatorData: toBase64Url(authData),
        signature: toBase64Url(sig),
        ...(userHandle ? { userHandle } : {}),
      },
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
    };
  }
}

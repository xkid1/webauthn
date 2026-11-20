import { readUint16BE, readUint32BE, WebAuthnError } from '@utils';

import type { TpmCertifyInfo, TpmPublicArea, TpmPublicKey } from '@types';

/**
 * Strict parsers for the two TPM 2.0 structures carried by "tpm" attestation
 * (TPM 2.0 Library, Part 2): TPMT_PUBLIC (`pubArea`) and TPMS_ATTEST (`certInfo`).
 * All reads are bounds-checked and trailing bytes are rejected.
 */

export const TPM_ALG = {
  RSA: 0x0001,
  SHA1: 0x0004,
  SHA256: 0x000b,
  SHA384: 0x000c,
  SHA512: 0x000d,
  NULL: 0x0010,
  ECC: 0x0023,
} as const;

export const TPM_ECC_CURVE = {
  NIST_P256: 0x0003,
  NIST_P384: 0x0004,
  NIST_P521: 0x0005,
} as const;

export const TPM_GENERATED_VALUE = 0xff544347;
export const TPM_ST_ATTEST_CERTIFY = 0x8017;

const invalid = (message: string): never => {
  throw new WebAuthnError('ATTESTATION_INVALID', `tpm: ${message}`);
};

class Reader {
  private offset = 0;
  constructor(
    private readonly bytes: Uint8Array,
    private readonly what: string,
  ) {}

  private need(n: number): number {
    const at = this.offset;
    if (at + n > this.bytes.length) invalid(`${this.what} is truncated`);
    this.offset += n;
    return at;
  }

  u8(): number {
    return this.bytes[this.need(1)]!;
  }
  u16(): number {
    return readUint16BE(this.bytes, this.need(2));
  }
  u32(): number {
    return readUint32BE(this.bytes, this.need(4));
  }
  raw(n: number): Uint8Array {
    const at = this.need(n);
    return this.bytes.subarray(at, at + n);
  }
  /** TPM2B_*: UINT16 size followed by that many bytes. */
  sized(): Uint8Array {
    return this.raw(this.u16());
  }
  end(): void {
    if (this.offset !== this.bytes.length) invalid(`${this.what} has trailing bytes`);
  }
}

/** TPMT_PUBLIC. Only signing keys (symmetric = TPM_ALG_NULL) are accepted. */
export function parsePubArea(bytes: Uint8Array): TpmPublicArea {
  const r = new Reader(bytes, 'pubArea');
  const type = r.u16();
  const nameAlg = r.u16();
  const objectAttributes = r.u32();
  r.sized(); // authPolicy

  if (r.u16() !== TPM_ALG.NULL) invalid('pubArea symmetric must be TPM_ALG_NULL');
  // scheme: TPM_ALG_NULL, or a signing scheme followed by its hashAlg
  if (r.u16() !== TPM_ALG.NULL) r.u16();

  let key: TpmPublicKey;
  if (type === TPM_ALG.RSA) {
    const keyBits = r.u16();
    const exponent = r.u32();
    const n = r.sized();
    if (keyBits !== n.length * 8)
      invalid('pubArea keyBits does not match modulus length');
    key = { type: 'RSA', exponent, n };
  } else if (type === TPM_ALG.ECC) {
    const curveId = r.u16();
    if (r.u16() !== TPM_ALG.NULL) r.u16(); // kdf + hashAlg
    const x = r.sized();
    const y = r.sized();
    key = { type: 'ECC', curveId, x, y };
  } else {
    return invalid('unsupported pubArea type');
  }
  r.end();
  return { nameAlg, objectAttributes, key };
}

/** TPMS_ATTEST whose `attested` member is a TPMS_CERTIFY_INFO. */
export function parseCertInfo(bytes: Uint8Array): TpmCertifyInfo {
  const r = new Reader(bytes, 'certInfo');
  const magic = r.u32();
  const type = r.u16();
  r.sized(); // qualifiedSigner
  const extraData = r.sized();
  r.raw(8); // clockInfo.clock
  r.u32(); // clockInfo.resetCount
  r.u32(); // clockInfo.restartCount
  r.u8(); // clockInfo.safe
  r.raw(8); // firmwareVersion
  const attestedName = r.sized();
  r.sized(); // qualifiedName
  r.end();
  return { magic, type, extraData, attestedName };
}

import type { CborMap } from '../cbor/index.js';
import type { CryptoLike } from '../runtime/index.js';

/** The decoded top-level attestationObject map. */
export interface AttestationObject {
  readonly fmt: string;
  readonly attStmt: CborMap;
  readonly authData: Uint8Array;
}

/** Input for `verifyCertificateChain` (leaf first, DER). */
export interface CertificateChainOptions {
  crypto: CryptoLike;
  chain: readonly Uint8Array[];
  trustAnchors: readonly Uint8Array[];
  now: number;
}

/* ---------------- android-key (§8.4): Keymaster / KeyMint KeyDescription ---------------- */

export interface AndroidKeyAuthorizationList {
  readonly purposes: readonly number[] | undefined;
  readonly origin: number | undefined;
  readonly allApplications: boolean;
}

export interface AndroidKeyDescription {
  readonly attestationChallenge: Uint8Array;
  readonly softwareEnforced: AndroidKeyAuthorizationList;
  readonly teeEnforced: AndroidKeyAuthorizationList;
}

/* ---------------- tpm (§8.3): TPM 2.0 structures ---------------- */

export type TpmPublicKey =
  | { readonly type: 'RSA'; readonly exponent: number; readonly n: Uint8Array }
  | {
      readonly type: 'ECC';
      readonly curveId: number;
      readonly x: Uint8Array;
      readonly y: Uint8Array;
    };

/** TPMT_PUBLIC (`pubArea`). */
export interface TpmPublicArea {
  readonly nameAlg: number;
  readonly objectAttributes: number;
  readonly key: TpmPublicKey;
}

/** TPMS_ATTEST with a TPMS_CERTIFY_INFO body (`certInfo`). */
export interface TpmCertifyInfo {
  readonly magic: number;
  readonly type: number;
  readonly extraData: Uint8Array;
  /** attested.name: nameAlg (UINT16) || H_nameAlg(pubArea). */
  readonly attestedName: Uint8Array;
}

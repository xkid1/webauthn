import { WebAuthnError } from '@utils';

import { decodeCbor, isCborMap } from '../cbor';

import type { AttestationObject, CborMap, CborValue } from '@types';

const invalid = (message: string): never => {
  throw new WebAuthnError('ATTESTATION_INVALID', `attestation: ${message}`);
};

export function parseAttestationObject(bytes: Uint8Array): AttestationObject {
  const value = decodeCbor(bytes);
  if (!isCborMap(value)) return invalid('attestationObject is not a map');
  const fmt = value.get('fmt');
  const attStmt = value.get('attStmt');
  const authData = value.get('authData');
  if (typeof fmt !== 'string' || fmt.length === 0) invalid('missing "fmt"');
  if (!isCborMap(attStmt ?? null)) invalid('missing "attStmt"');
  if (!(authData instanceof Uint8Array)) invalid('missing "authData"');
  return {
    fmt: fmt as string,
    attStmt: attStmt as CborMap,
    authData: authData as Uint8Array,
  };
}

export const stmtBytes = (stmt: CborMap, key: string): Uint8Array => {
  const v = stmt.get(key);
  return v instanceof Uint8Array ? v : invalid(`"${key}" must be a byte string`);
};

export const stmtNumber = (stmt: CborMap, key: string): number => {
  const v = stmt.get(key);
  return typeof v === 'number' ? v : invalid(`"${key}" must be an integer`);
};

/** x5c: non-empty array of DER certificates, or undefined when absent. */
export function stmtCertificates(stmt: CborMap): Uint8Array[] | undefined {
  const v: CborValue = stmt.get('x5c');
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || v.length === 0)
    return invalid('"x5c" must be a non-empty array');
  return v.map((c) =>
    c instanceof Uint8Array ? c : invalid('"x5c" entries must be byte strings'),
  );
}

export function assertOnlyKeys(stmt: CborMap, allowed: readonly string[]): void {
  for (const key of stmt.keys()) {
    if (typeof key !== 'string' || !allowed.includes(key))
      invalid(`unexpected attStmt field`);
  }
}

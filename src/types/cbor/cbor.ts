/** A JSON-compatible CBOR data model (RFC 8949) as decoded by this package. */
export type CborValue =
  | number
  | bigint
  | string
  | boolean
  | null
  | undefined
  | Uint8Array
  | CborValue[]
  | CborMap;

export type CborMap = Map<CborValue, CborValue>;

export interface CborDecodeOptions {
  /** Maximum nesting depth. Default 16. */
  readonly maxDepth?: number;
  /** Maximum total number of decoded items. Default 4096. */
  readonly maxItems?: number;
}

/** Result of `decodeCborFirst`: the first item and how many bytes it used. */
export interface CborDecodeResult {
  readonly value: CborValue;
  readonly length: number;
}

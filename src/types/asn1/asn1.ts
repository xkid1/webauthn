/** One DER tag-length-value header, as offsets into the source bytes. */
export interface Tlv {
  /** First identifier octet (class, constructed bit and low tag number). */
  readonly tag: number;
  /** Tag number; differs from `tag & 0x1f` only for high-tag-number form. */
  readonly tagNumber: number;
  /** Offset of the first header byte. */
  readonly offset: number;
  /** Offset of the first content byte. */
  readonly start: number;
  /** Offset one past the last content byte. */
  readonly end: number;
}

export interface X509Extension {
  readonly critical: boolean;
  /** Content of the extnValue OCTET STRING. */
  readonly value: Uint8Array;
}

export interface X509Certificate {
  readonly raw: Uint8Array;
  readonly version: number;
  /** DER of tbsCertificate – the signed bytes. */
  readonly tbs: Uint8Array;
  readonly signatureAlgorithm: string;
  readonly signature: Uint8Array;
  readonly issuer: Uint8Array;
  readonly subject: Uint8Array;
  readonly subjectAttributes: ReadonlyMap<string, string>;
  readonly notBefore: number;
  readonly notAfter: number;
  /** DER SubjectPublicKeyInfo. */
  readonly spki: Uint8Array;
  readonly publicKeyAlgorithm: string;
  readonly publicKeyCurve?: 'P-256' | 'P-384' | 'P-521';
  readonly extensions: ReadonlyMap<string, X509Extension>;
}

/** RSAPublicKey ::= SEQUENCE { modulus, publicExponent } with leading zeros stripped. */
export interface RsaPublicKey {
  readonly n: Uint8Array;
  readonly e: Uint8Array;
}

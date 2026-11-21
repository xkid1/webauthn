import type { Base64URLString, CollectedClientData } from '../webauthn';

export interface ParsedClientData {
  readonly raw: Uint8Array;
  readonly data: CollectedClientData;
}

/** What `verifyClientData` checks the parsed client data against. */
export interface ClientDataExpectations {
  readonly type: CollectedClientData['type'];
  readonly challenge: Base64URLString;
  readonly origins: readonly string[];
  readonly allowCrossOrigin: boolean;
  readonly allowedTopOrigins: readonly string[];
}

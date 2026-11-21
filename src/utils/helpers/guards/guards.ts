import { WebAuthnError } from '../error';

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new WebAuthnError('INVALID_INPUT', `"${field}" must be a non-empty string`);
  }
  return value;
}

export function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (!isRecord(value))
    throw new WebAuthnError('INVALID_INPUT', `"${field}" must be an object`);
  return value;
}

/**
 * Validate an RP ID: a lowercase registrable domain or "localhost".
 * IP addresses are forbidden by the WebAuthn spec.
 */
export function isValidRpId(rpId: string): boolean {
  if (rpId === 'localhost') return true;
  if (rpId.length === 0 || rpId.length > 253) return false;
  const labels = rpId.split('.');
  if (labels.length < 2 || labels.every((l) => /^[0-9]+$/u.test(l))) return false; // IPv4 / single label
  return labels.every(isDnsLabel);
}

/** One DNS label: 1–63 chars of a-z 0-9 '-', not starting/ending with '-'. */
export const isDnsLabel = (label: string): boolean =>
  label.length > 0 &&
  label.length <= 63 &&
  /^[a-z0-9-]+$/u.test(label) &&
  !label.startsWith('-') &&
  !label.endsWith('-');

/**
 * Accept only secure origins: https://host[:port], http://localhost[:port],
 * or Android facet origins (android:apk-key-hash:<base64url sha256>).
 */
export function isValidOrigin(origin: string): boolean {
  if (/^android:apk-key-hash:[A-Za-z0-9_-]{43}$/u.test(origin)) return true;
  // Linear-time: no nested quantifiers.
  // eslint-disable-next-line security/detect-unsafe-regex
  const match = /^(https?):\/\/([a-z0-9.-]+)(:\d{1,5})?$/u.exec(origin);
  if (!match) return false;
  const [, scheme, host] = match;
  if (!host?.split('.').every(isDnsLabel)) return false;
  if (scheme === 'http') return host === 'localhost' || host.endsWith('.localhost');
  return true;
}

/** Host part of an https/http origin, or undefined for non-web origins. */
export function originHost(origin: string): string | undefined {
  // eslint-disable-next-line security/detect-unsafe-regex -- linear, no nested quantifiers
  return /^https?:\/\/([a-z0-9.-]+)(?::\d{1,5})?$/u.exec(origin)?.[1];
}

/** True when `host` equals `rpId` or is a subdomain of it (WebAuthn §5.1.4.1 step 8). */
export const isHostWithinRpId = (host: string, rpId: string): boolean =>
  host === rpId || host.endsWith(`.${rpId}`);

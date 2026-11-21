import { getErrorHint } from './hints';

import type {
  WebAuthnErrorCode,
  WebAuthnErrorJSON,
  WebAuthnErrorOptions,
  WithErrorCode,
} from '@types';

/**
 * The only error type thrown by this package. Switch on `code`, never on `message`.
 *
 * - `message` says what went wrong.
 * - `hint` says how to fix it.
 * - `cause` (when present) is the underlying error, e.g. a DOMException.
 *
 * Messages and hints are written for developers and never echo secret material
 * (challenges, keys, signatures, user handles), so they are safe to log.
 * `toJSON()` is safe to return from an API; it omits `cause` and the stack.
 *
 * @example
 * try {
 *   await verifyRegistrationResponse(config, input);
 * } catch (error) {
 *   if (isWebAuthnError(error, 'CHALLENGE_NOT_FOUND')) return restartCeremony();
 *   if (isWebAuthnError(error)) {
 *     console.warn(String(error)); // "WebAuthnError [ORIGIN_MISMATCH]: … Hint: …"
 *     return res.status(400).json(error.toJSON());
 *   }
 *   throw error;
 * }
 */
export class WebAuthnError extends Error {
  override readonly name = 'WebAuthnError';
  readonly code: WebAuthnErrorCode;
  /** Actionable guidance for the developer: how to fix or handle this error. */
  readonly hint: string;

  constructor(code: WebAuthnErrorCode, message: string, options?: WebAuthnErrorOptions) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.code = code;
    this.hint = options?.hint ?? getErrorHint(code);
  }

  /** Serializable, log- and API-safe view. Excludes `cause` and `stack`. */
  toJSON(): WebAuthnErrorJSON {
    return { name: this.name, code: this.code, message: this.message, hint: this.hint };
  }

  override toString(): string {
    return `${this.name} [${this.code}]: ${this.message} Hint: ${this.hint}`;
  }
}

/**
 * `true` when `value` is a WebAuthnError, optionally with one of the given codes.
 * Use it to narrow `unknown` in a catch block.
 */
export function isWebAuthnError<C extends WebAuthnErrorCode>(
  value: unknown,
  ...codes: readonly C[]
): value is WebAuthnError & WithErrorCode<C> {
  return (
    value instanceof WebAuthnError &&
    (codes.length === 0 || codes.includes(value.code as C))
  );
}

/** Throw a WebAuthnError unless `condition` holds. */
export function ensure(
  condition: unknown,
  code: WebAuthnErrorCode,
  message: string,
): asserts condition {
  if (!condition) throw new WebAuthnError(code, message);
}

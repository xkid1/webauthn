import { isRecord, WebAuthnError } from '@utils';

import { createAbortController } from '../environment';

import type {
  AbortControllerLike,
  AbortSignalLike,
  CeremonyHandle,
  WebAuthnErrorCode,
} from '@types';

/**
 * Only one WebAuthn ceremony can run per page. Starting a new one aborts the
 * previous (e.g. a pending passkey-autofill request when the user clicks
 * "Sign in with passkey"). Framework-agnostic: works with React StrictMode
 * double-effects, Vue/Svelte remounts and Angular route changes.
 */
let active: AbortControllerLike | undefined;

const SUPERSEDED = 'webauthn-ceremony-superseded';

export function beginCeremony(external?: AbortSignalLike): CeremonyHandle {
  active?.abort(new WebAuthnError('CEREMONY_ABORTED', SUPERSEDED));
  const controller = createAbortController();
  active = controller;

  if (!controller) return { signal: external, end: () => undefined };

  const onAbort = (): void => {
    controller.abort(
      external?.reason ?? new WebAuthnError('CEREMONY_ABORTED', 'Aborted by caller'),
    );
  };
  if (external?.aborted) onAbort();
  else external?.addEventListener('abort', onAbort, { once: true });

  return {
    signal: controller.signal,
    end: () => {
      external?.removeEventListener('abort', onAbort);
      if (active === controller) active = undefined;
    },
  };
}

/** Abort whatever ceremony is in flight (call on route change / unmount). */
export function cancelCeremony(): void {
  active?.abort(new WebAuthnError('CEREMONY_ABORTED', 'Cancelled'));
  active = undefined;
}

const NAME_TO_CODE: Readonly<Record<string, WebAuthnErrorCode>> = {
  AbortError: 'CEREMONY_ABORTED',
  NotAllowedError: 'CEREMONY_NOT_ALLOWED',
  InvalidStateError: 'CREDENTIAL_EXCLUDED',
  SecurityError: 'SECURITY_ERROR',
  NotSupportedError: 'NOT_SUPPORTED',
  ConstraintError: 'CONSTRAINT_ERROR',
  TypeError: 'INVALID_INPUT',
};

const MESSAGES: Partial<Record<WebAuthnErrorCode, string>> = {
  CEREMONY_ABORTED: 'The ceremony was aborted',
  CEREMONY_NOT_ALLOWED:
    'The user cancelled, the request timed out, or no matching credential was available',
  CREDENTIAL_EXCLUDED: 'This authenticator is already registered for this account',
  SECURITY_ERROR: 'The rpId is not valid for this origin (check rpId / https)',
  NOT_SUPPORTED:
    'None of the requested algorithms or options are supported by the authenticator',
  CONSTRAINT_ERROR:
    'The authenticator cannot satisfy residentKey / userVerification requirements',
};

/** Normalise a DOMException (or anything) thrown by navigator.credentials into a WebAuthnError. */
export function toCeremonyError(error: unknown, signal?: AbortSignalLike): WebAuthnError {
  if (error instanceof WebAuthnError) return error;
  if (signal?.aborted) {
    const reason = signal.reason;
    return reason instanceof WebAuthnError
      ? reason
      : new WebAuthnError('CEREMONY_ABORTED', 'Ceremony aborted', { cause: error });
  }
  const name = isRecord(error) && typeof error.name === 'string' ? error.name : '';
  const code = NAME_TO_CODE[name] ?? 'UNKNOWN_ERROR';
  const detail =
    isRecord(error) && typeof error.message === 'string' ? error.message : String(error);
  return new WebAuthnError(code, MESSAGES[code] ?? detail, { cause: error });
}

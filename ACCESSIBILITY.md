# Accessibility

`@xkid1/webauthn` renders no UI. The browser, the operating system and the authenticator show the passkey prompts. Your application still owns everything around them: the sign-in form, the buttons that start a ceremony, and the messages people see when something goes wrong.

This document explains what the library does to support accessible passkey flows, and what you should do to build on it. The target is [WCAG 2.2](https://www.w3.org/TR/WCAG22/) level AA.

## Why passkeys help

Passkeys remove the need to remember, type or transcribe passwords and one-time codes. That benefits people with cognitive, motor or visual disabilities, and supports WCAG 2.2 success criterion **3.3.8 Accessible Authentication (Minimum)**. The unlock step (fingerprint, face, device PIN or security key) is handled by the platform, and platforms let people choose a method that works for them.

## What the library does

- **No UI of its own.** Nothing in the library injects markup, focus traps or styles, so it never conflicts with your design system or assistive technology.
- **Autofill (conditional UI) support.** `startAuthentication` with conditional mediation offers passkeys in the browser's native autofill list, which screen readers and keyboards already support. It checks for an `<input autocomplete="username webauthn">` and fails early with a clear error if there isn't one.
- **Generous, adjustable timeouts.** The default ceremony timeout is 5 minutes. You can set it anywhere from 10 seconds to 10 minutes with the `timeout` option. Some people need much longer than average to locate a security key or complete biometric or PIN entry (WCAG **2.2.1 Timing Adjustable**).
- **Cancellable ceremonies.** Starting a new ceremony aborts the previous one, and every call accepts an `AbortSignal`, so users are never stuck in a prompt they can't dismiss.
- **Errors you can explain.** Every failure is a `WebAuthnError` with a stable `code` and a developer `hint`. Map codes to plain-language messages instead of showing raw errors.
- **Feature detection.** `isWebAuthnSupported()` and `getClientCapabilities()` let you offer passkeys only where they work, and fall back gracefully elsewhere.

## What your application should do

### Forms and controls

- Use `<input autocomplete="username webauthn">` on the username field so passkeys appear in autofill.
- Give every control a visible label. Use a real `<button>` for "Sign in with a passkey" and "Create a passkey", and make sure it works with a keyboard alone.
- Don't start a ceremony automatically on page load, except conditional mediation. Let people choose when the prompt appears.

### Messages and errors

- Show messages in text, in an element with `role="status"` or `role="alert"` (an `aria-live` region), so screen readers announce them.
- Map `WebAuthnError` codes to messages that say what happened and what to do next. Keep the developer `hint` for logs. For example:

  | Code | Suggested message |
  | --- | --- |
  | `CEREMONY_NOT_ALLOWED` | "The passkey request was cancelled or timed out. Try again when you're ready." |
  | `CREDENTIAL_EXCLUDED` | "This device already has a passkey for your account." |
  | `NOT_SUPPORTED` | "This browser can't use passkeys. Sign in another way." |
  | `NETWORK_ERROR` | "We couldn't reach the server. Check your connection and try again." |

- Treat a cancelled ceremony as normal, not as an error. Return focus to the button that started it.
- Don't rely on color alone to show success or failure.

### Alternatives

- Always offer another way to sign in and to recover an account. Not everyone can use biometrics or a security key, and not every device supports passkeys.
- Explain passkeys in plain language the first time you offer one, for example "Sign in with your fingerprint, face or screen lock instead of a password."
- Let people manage their passkeys (list, rename, remove) with an accessible settings page.

### Timing

- Don't shorten `timeout` below what your users need. If you use a short timeout, tell people beforehand and let them restart the ceremony easily.

## Documentation

We aim to keep the README and guides readable: descriptive headings, plain language, code examples with surrounding explanation, and tables with header rows. If something in the docs is hard to read or navigate with assistive technology, please tell us.

## Feedback

Accessibility problems are bugs. Report them with the [bug report form](https://github.com/xkid1/webauthn/issues/new/choose) and mention "accessibility" in the title. Include your browser, assistive technology and operating system if they matter. Contributions that improve accessibility guidance are welcome; see [Contributing.md](./Contributing.md).

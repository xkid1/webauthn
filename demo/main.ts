import {
  cancelCeremony,
  createWebAuthnClient,
  getClientCapabilities,
  getErrorHint,
  isWebAuthnError,
  signals,
  startAuthentication,
} from '@xkid1/webauthn/client';

import { setupSettings } from './settings.js';

import type { FetchLike } from '@xkid1/webauthn/client';

const getSettings = setupSettings();

/** Log the options the server generated, so the effect of each setting is visible. */
const loggingFetch: FetchLike = async (url, init) => {
  const res = await fetch(url, init as RequestInit);
  if (res.ok && url.endsWith('/options')) {
    const data: unknown = await res.clone().json();
    log('info', `Options from ${url}`, data);
  }
  return res;
};

const client = createWebAuthnClient({ fetch: loggingFetch });

const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} missing`);
  return el as T;
};

const username = $<HTMLInputElement>('username');
const autofill = $<HTMLInputElement>('autofill');
const logList = $<HTMLOListElement>('log');
const buttons = ['register', 'login', 'login-any'].map((id) => $<HTMLButtonElement>(id));

type Level = 'info' | 'ok' | 'error';

function log(level: Level, title: string, detail?: unknown): void {
  const item = document.createElement('li');
  item.className = level;
  const head = document.createElement('div');
  head.className = 'head';
  const time = document.createElement('time');
  time.textContent = new Date().toLocaleTimeString();
  const text = document.createElement('span');
  text.textContent = title;
  head.append(time, text);
  item.append(head);
  if (detail !== undefined) {
    const pre = document.createElement('pre');
    pre.textContent =
      typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2);
    item.append(pre);
  }
  logList.prepend(item);
}

function logError(action: string, error: unknown): void {
  if (isWebAuthnError(error)) {
    log('error', `${action} failed: ${error.code}`, {
      message: error.message,
      hint: getErrorHint(error.code),
    });
  } else {
    log(
      'error',
      `${action} failed`,
      error instanceof Error ? error.message : String(error),
    );
  }
}

function busy(on: boolean): void {
  for (const b of buttons) b.disabled = on;
}

async function run(action: string, task: () => Promise<unknown>): Promise<void> {
  busy(true);
  log('info', `${action}…`);
  try {
    log('ok', `${action} succeeded`, await task());
    await refreshUsers();
  } catch (error) {
    logError(action, error);
  } finally {
    busy(false);
  }
}

function requireName(): string | undefined {
  const name = username.value.trim();
  if (!name) {
    log('error', 'Enter a username first');
    username.focus();
  }
  return name || undefined;
}

// ── Environment ──────────────────────────────────────────────────────────────

async function showSupport(): Promise<void> {
  const caps = await getClientCapabilities();
  const list = $<HTMLUListElement>('support');
  const rows: [string, boolean][] = [
    ['WebAuthn (secure context)', caps.webauthn],
    ['Platform authenticator', caps.platformAuthenticator],
    ['Passkey autofill (conditionalGet)', caps.conditionalGet],
    ['Conditional create', caps.conditionalCreate],
    ['Hybrid transport (phone)', caps.hybridTransport],
  ];
  list.replaceChildren(
    ...rows.map(([label, ok]) => {
      const li = document.createElement('li');
      li.className = ok ? 'yes' : 'no';
      li.textContent = label;
      return li;
    }),
  );
  autofill.disabled = !caps.conditionalGet;
  if (!caps.webauthn) {
    log('error', 'WebAuthn is unavailable. Open the demo at http://localhost:5173.');
  }
}

// ── Server state ─────────────────────────────────────────────────────────────

interface DemoUserView {
  readonly name: string;
  readonly credentials: readonly { readonly id: string; readonly counter: number }[];
}

async function postJSON(path: string, body: unknown = {}): Promise<unknown> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(body),
  });
  const data: unknown = await res.json().catch(() => undefined);
  if (!res.ok) {
    const message =
      typeof data === 'object' && data !== null && 'message' in data
        ? String(data.message)
        : `HTTP ${res.status}`;
    throw new Error(message);
  }
  return data;
}

function smallButton(text: string, onClick: () => void): HTMLButtonElement {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'ghost small danger';
  button.textContent = text;
  button.addEventListener('click', onClick);
  return button;
}

async function refreshUsers(): Promise<void> {
  const users = (await postJSON('/webauthn/users')) as DemoUserView[];
  const list = $<HTMLUListElement>('users');
  $('refreshed').textContent = `Updated ${new Date().toLocaleTimeString()}`;
  if (users.length === 0) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = 'Nothing yet. Register a passkey above.';
    list.replaceChildren(li);
    return;
  }
  list.replaceChildren(
    ...users.map((u) => {
      const li = document.createElement('li');
      const head = document.createElement('div');
      head.className = 'user-head';
      const strong = document.createElement('strong');
      strong.textContent = u.name;
      head.append(strong);
      if (u.credentials.length > 1) {
        head.append(
          smallButton('Remove all', () => void removeCredentials(u.name, u.credentials)),
        );
      }
      const creds = document.createElement('ul');
      creds.className = 'creds';
      for (const c of u.credentials) {
        const row = document.createElement('li');
        const label = document.createElement('small');
        label.textContent = `${c.id.slice(0, 16)}… (counter ${c.counter})`;
        label.title = c.id;
        row.append(
          label,
          smallButton('Remove', () => void removeCredentials(u.name, [c])),
        );
        creds.append(row);
      }
      li.append(head, creds);
      return li;
    }),
  );
}

async function manualRefresh(): Promise<void> {
  const button = $<HTMLButtonElement>('refresh');
  button.disabled = true;
  button.textContent = 'Refreshing…';
  try {
    await refreshUsers();
  } catch (error) {
    logError('Refresh', error);
  } finally {
    button.disabled = false;
    button.textContent = 'Refresh';
  }
}

async function removeCredentials(
  username: string,
  credentials: DemoUserView['credentials'],
): Promise<void> {
  const all = credentials.length > 1;
  try {
    const result = await postJSON(
      '/webauthn/credentials/remove',
      all ? { username } : { username, credentialId: credentials[0]?.id },
    );
    // Tell the browser / password manager these passkeys are gone (Signal API).
    const signalled = await Promise.all(
      credentials.map((c) => signals.unknownCredential(location.hostname, c.id)),
    );
    log('ok', `Removed ${all ? 'all passkeys' : 'a passkey'} of "${username}"`, {
      ...(result as object),
      browserSignalled: signalled.every(Boolean),
    });
  } catch (error) {
    logError('Remove passkey', error);
  }
  await refreshUsers().catch((error: unknown) => logError('Refresh', error));
}

// ── Passkey autofill (conditional mediation) ─────────────────────────────────

let autofillController: AbortController | undefined;

async function startAutofill(): Promise<void> {
  autofillController?.abort();
  const controller = new AbortController();
  autofillController = controller;
  log('info', 'Waiting for a passkey from the username autofill…');
  try {
    // Lower-level API: fetch options yourself, run the ceremony, POST the result.
    const optionsRes = await fetch('/webauthn/authenticate/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ settings: getSettings() }),
    });
    const optionsJSON: unknown = await optionsRes.json();
    if (!optionsRes.ok) throw new Error(JSON.stringify(optionsJSON));
    const response = await startAuthentication({
      optionsJSON: optionsJSON as Parameters<
        typeof startAuthentication
      >[0]['optionsJSON'],
      useBrowserAutofill: true,
      signal: controller.signal,
    });
    const verifyRes = await fetch('/webauthn/authenticate/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ response }),
    });
    const result: unknown = await verifyRes.json();
    if (!verifyRes.ok) throw new Error(JSON.stringify(result));
    log('ok', 'Autofill sign-in succeeded', result);
    await refreshUsers();
  } catch (error) {
    if (controller.signal.aborted) return;
    logError('Autofill sign-in', error);
  } finally {
    if (autofillController === controller) {
      autofillController = undefined;
      autofill.checked = false;
    }
  }
}

function stopAutofill(): void {
  autofillController?.abort();
  autofillController = undefined;
}

// ── Wiring ───────────────────────────────────────────────────────────────────

$('register').addEventListener('click', () => {
  const name = requireName();
  if (!name) return;
  stopAutofill();
  void run(`Register "${name}"`, () =>
    client.register({ username: name, settings: getSettings() }),
  );
});

$('login').addEventListener('click', () => {
  const name = requireName();
  if (!name) return;
  stopAutofill();
  void run(`Sign in as "${name}"`, () =>
    client.authenticate({ username: name, settings: getSettings() }),
  );
});

$('login-any').addEventListener('click', () => {
  stopAutofill();
  void run('Sign in with a discoverable passkey', () =>
    client.authenticate({ settings: getSettings() }),
  );
});

$('cancel').addEventListener('click', () => {
  stopAutofill();
  cancelCeremony();
  log('info', 'Cancelled the pending ceremony');
});

autofill.addEventListener('change', () => {
  if (autofill.checked) void startAutofill();
  else stopAutofill();
});

$('refresh').addEventListener('click', () => void manualRefresh());
$('clear').addEventListener('click', () => logList.replaceChildren());
$('form').addEventListener('submit', (event) => event.preventDefault());

void showSupport();
void manualRefresh();

import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vite';

import type * as ServerSide from './src/apps/server-side/index.js';
import type {
  AttestationConveyancePreference,
  AuthenticationResponseJSON,
  AuthenticatorAttachment,
  AuthenticatorSelectionCriteria,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialHint,
  RegistrationResponseJSON,
  ResidentKeyRequirement,
  StoredCredential,
  UserVerificationRequirement,
  WebAuthnServer,
} from './src/types/index.js';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Plugin, ViteDevServer } from 'vite';

/**
 * Local demo for the client-side entry point (`yarn demo`).
 *
 * The browser page in `demo/` uses `@xkid1/webauthn/client` from source. A tiny
 * in-memory relying party is mounted as dev-server middleware and built from the
 * server-side entry point, so both halves of the ceremony run for real.
 * Development only: users, credentials and sessions live in memory.
 */

// `DEMO_PORT=5174 yarn demo` runs a second, independent instance.
const PORT = Number(process.env.DEMO_PORT ?? 5173);
const RP_ID = 'localhost';
const ORIGIN = `http://${RP_ID}:${PORT}`;

const fromRoot = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

type ServerModule = typeof ServerSide;

/** Algorithms the demo lets you pick. Must stay within what `getAlgorithmSpec` supports. */
const OFFERED_ALGORITHMS: readonly COSEAlgorithmIdentifier[] = [
  -8, // EdDSA
  -19, // Ed25519
  -7, // ES256
  -35, // ES384
  -36, // ES512
  -37, // PS256
  -257, // RS256
];
const DEFAULT_ALGORITHMS: readonly COSEAlgorithmIdentifier[] = [-8, -7, -257];

const USER_VERIFICATION = ['required', 'preferred', 'discouraged'] as const;
const RESIDENT_KEY = ['required', 'preferred', 'discouraged'] as const;
const ATTACHMENT = ['all', 'platform', 'cross-platform'] as const;
const ATTESTATION = ['none', 'indirect', 'direct', 'enterprise'] as const;
const HINTS = ['security-key', 'client-device', 'hybrid'] as const;

interface RegistrationSettings {
  readonly userVerification: UserVerificationRequirement;
  readonly attachment: AuthenticatorAttachment | 'all';
  readonly residentKey: ResidentKeyRequirement;
  readonly attestation: AttestationConveyancePreference;
  readonly algorithms: readonly COSEAlgorithmIdentifier[];
  readonly hints: readonly PublicKeyCredentialHint[];
}

interface AuthenticationSettings {
  readonly userVerification: UserVerificationRequirement;
  readonly hints: readonly PublicKeyCredentialHint[];
}

interface DemoUser {
  readonly id: string;
  readonly name: string;
  readonly credentials: StoredCredential[];
}

interface DemoBody {
  readonly username?: unknown;
  readonly response?: unknown;
  readonly settings?: unknown;
  readonly credentialId?: unknown;
}

interface PendingRegistration {
  readonly name: string;
  readonly id: string;
  readonly rp: WebAuthnServer;
  readonly requireUserVerification: boolean;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

// ── Settings parsing: the browser is untrusted, so everything is allowlisted ──

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.includes(value as T) ? (value as T) : fallback;
}

/** Ordered, de-duplicated subset of `allowed`; unknown entries are dropped. */
function orderedSubset<T>(value: unknown, allowed: readonly T[]): T[] {
  if (!Array.isArray(value)) return [];
  const out: T[] = [];
  for (const item of value as unknown[]) {
    if (allowed.includes(item as T) && !out.includes(item as T)) out.push(item as T);
  }
  return out;
}

function registrationSettings(body: DemoBody): RegistrationSettings {
  const s =
    isObject(body.settings) && isObject(body.settings.registration)
      ? body.settings.registration
      : {};
  const algorithms = orderedSubset(s.algorithms, OFFERED_ALGORITHMS);
  if (Array.isArray(s.algorithms) && algorithms.length === 0) {
    throw new HttpError(400, 'Select at least one public key algorithm');
  }
  return {
    userVerification: oneOf(s.userVerification, USER_VERIFICATION, 'preferred'),
    attachment: oneOf(s.attachment, ATTACHMENT, 'all'),
    residentKey: oneOf(s.residentKey, RESIDENT_KEY, 'preferred'),
    attestation: oneOf(s.attestation, ATTESTATION, 'none'),
    algorithms: algorithms.length > 0 ? algorithms : DEFAULT_ALGORITHMS,
    hints: orderedSubset(s.hints, HINTS),
  };
}

function authenticationSettings(body: DemoBody): AuthenticationSettings {
  const s =
    isObject(body.settings) && isObject(body.settings.authentication)
      ? body.settings.authentication
      : {};
  return {
    userVerification: oneOf(s.userVerification, USER_VERIFICATION, 'preferred'),
    hints: orderedSubset(s.hints, HINTS),
  };
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<DemoBody> {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => {
      raw += chunk;
      if (raw.length > 64 * 1024) reject(new HttpError(413, 'Body too large'));
    });
    req.on('end', () => {
      try {
        const parsed: unknown = raw ? JSON.parse(raw) : {};
        resolve(isObject(parsed) ? parsed : {});
      } catch {
        reject(new HttpError(400, 'Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sessionId(req: IncomingMessage, res: ServerResponse): string {
  const match = /(?:^|;\s*)demo_sid=([\w-]+)/u.exec(req.headers.cookie ?? '');
  if (match?.[1]) return match[1];
  const sid = randomBytes(16).toString('base64url');
  res.setHeader('Set-Cookie', `demo_sid=${sid}; Path=/; HttpOnly; SameSite=Strict`);
  return sid;
}

function send(res: ServerResponse, status: number, data: unknown): void {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(data));
}

function requireUsername(body: DemoBody): string {
  const name = typeof body.username === 'string' ? body.username.trim() : '';
  if (!name || name.length > 64)
    throw new HttpError(400, 'username is required (≤ 64 chars)');
  return name;
}

// ── Relying party ────────────────────────────────────────────────────────────

function createRelyingParty(lib: ServerModule) {
  const users = new Map<string, DemoUser>();
  // Settings chosen at the options step are remembered server-side, so the
  // verify step cannot be relaxed by sending different settings.
  const pendingRegistrations = new Map<string, PendingRegistration>();
  const pendingAuthentications = new Map<string, boolean>();
  // One store shared by every RP instance: keys are per ceremony + session.
  const challengeStore = new lib.MemoryChallengeStore();
  // `supportedAlgorithms` is relying-party config, so build one RP per selection.
  const rps = new Map<string, WebAuthnServer>();
  const rpFor = (algorithms: readonly COSEAlgorithmIdentifier[]): WebAuthnServer => {
    const key = algorithms.join(',');
    let rp = rps.get(key);
    if (!rp) {
      rp = lib.createWebAuthnServer({
        rpId: RP_ID,
        rpName: 'webauthn demo',
        origins: [ORIGIN],
        supportedAlgorithms: algorithms,
        challengeStore,
      });
      rps.set(key, rp);
    }
    return rp;
  };
  // Sign-in accepts every algorithm a credential could have been registered with.
  const authRp = rpFor(OFFERED_ALGORITHMS);

  const findByCredential = (id: string) => {
    for (const user of users.values()) {
      const index = user.credentials.findIndex((c) => c.id === id);
      if (index !== -1) return { user, index };
    }
    return undefined;
  };

  return {
    async registrationOptions(sid: string, body: DemoBody) {
      const name = requireUsername(body);
      const settings = registrationSettings(body);
      const existing = users.get(name);
      // The user handle must be stable per account: reuse it, or mint one and
      // remember it for this session until the verify step creates the account.
      const id = existing?.id ?? lib.toBase64Url(randomBytes(16));
      const rp = rpFor(settings.algorithms);
      pendingRegistrations.set(sid, {
        name,
        id,
        rp,
        requireUserVerification: settings.userVerification === 'required',
      });
      const authenticatorSelection: AuthenticatorSelectionCriteria = {
        residentKey: settings.residentKey,
        userVerification: settings.userVerification,
        ...(settings.attachment === 'all'
          ? {}
          : { authenticatorAttachment: settings.attachment }),
      };
      return rp.generateRegistrationOptions({
        sessionKey: sid,
        user: { id, name, displayName: name },
        excludeCredentials: existing?.credentials ?? [],
        authenticatorSelection,
        attestation: settings.attestation,
        hints: settings.hints,
        extensions: { credProps: true },
      });
    },

    async registrationVerify(sid: string, body: DemoBody) {
      const started = pendingRegistrations.get(sid);
      pendingRegistrations.delete(sid);
      if (!started) throw new HttpError(400, 'No registration in progress');
      const result = await started.rp.verifyRegistration({
        sessionKey: sid,
        response: body.response as RegistrationResponseJSON,
        requireUserVerification: started.requireUserVerification,
      });
      const user = users.get(started.name) ?? {
        id: started.id,
        name: started.name,
        credentials: [],
      };
      user.credentials.push({
        id: result.credential.id,
        publicKey: result.credential.publicKey,
        counter: result.credential.counter,
        transports: result.credential.transports,
      });
      users.set(user.name, user);
      return {
        verified: true,
        username: user.name,
        credential: result.credential,
        userVerified: result.userVerified,
        origin: result.origin,
        attestation: {
          format: result.attestation.format,
          type: result.attestation.type,
          trusted: result.attestation.trusted,
        },
      };
    },

    async authenticationOptions(sid: string, body: DemoBody) {
      const settings = authenticationSettings(body);
      const name = typeof body.username === 'string' ? body.username.trim() : '';
      const user = name ? users.get(name) : undefined;
      if (name && !user) throw new HttpError(404, `No passkeys registered for "${name}"`);
      pendingAuthentications.set(sid, settings.userVerification === 'required');
      return authRp.generateAuthenticationOptions({
        sessionKey: sid,
        userVerification: settings.userVerification,
        hints: settings.hints,
        ...(user ? { allowCredentials: user.credentials } : {}),
      });
    },

    async authenticationVerify(sid: string, body: DemoBody) {
      const requireUserVerification = pendingAuthentications.get(sid);
      pendingAuthentications.delete(sid);
      if (requireUserVerification === undefined) {
        throw new HttpError(400, 'No sign-in in progress');
      }
      const response = body.response as AuthenticationResponseJSON | undefined;
      const found =
        typeof response?.id === 'string' ? findByCredential(response.id) : undefined;
      if (!response || !found) throw new HttpError(404, 'Unknown credential');
      const { user, index } = found;
      const credential = user.credentials[index];
      if (!credential) throw new HttpError(404, 'Unknown credential');
      const result = await authRp.verifyAuthentication({
        sessionKey: sid,
        response,
        credential,
        expectedUserHandle: user.id,
        requireUserVerification,
      });
      user.credentials[index] = { ...credential, counter: result.newCounter };
      return { verified: true, username: user.name, ...result };
    },

    list() {
      return [...users.values()].map((u) => ({
        name: u.name,
        credentials: u.credentials.map((c) => ({ id: c.id, counter: c.counter })),
      }));
    },

    /**
     * Remove one credential (`credentialId`) or every credential of a user
     * (`username` only). A user with no credentials left is removed too.
     * Demo only: there is no sign-in check, anyone on the page can remove.
     */
    removeCredentials(body: DemoBody) {
      const name = requireUsername(body);
      const user = users.get(name);
      if (!user) throw new HttpError(404, `Unknown user "${name}"`);
      const credentialId =
        typeof body.credentialId === 'string' ? body.credentialId : undefined;
      const removed = credentialId
        ? user.credentials.filter((c) => c.id === credentialId).map((c) => c.id)
        : user.credentials.map((c) => c.id);
      if (removed.length === 0) throw new HttpError(404, 'Unknown credential');
      const remaining = user.credentials.filter((c) => !removed.includes(c.id));
      if (remaining.length === 0) users.delete(name);
      else users.set(name, { ...user, credentials: remaining });
      return { removed, userRemoved: remaining.length === 0 };
    },
  };
}

function demoRelyingParty(): Plugin {
  return {
    name: 'webauthn-demo-rp',
    apply: 'serve',
    configureServer(server: ViteDevServer) {
      let ready: Promise<ReturnType<typeof createRelyingParty>> | undefined;
      const load = async () => {
        const lib = (await server.ssrLoadModule(
          fromRoot('./src/apps/server-side/index.ts'),
        )) as ServerModule;
        return createRelyingParty(lib);
      };

      server.middlewares.use('/webauthn', (req, res, next) => {
        if (req.method !== 'POST') {
          next();
          return;
        }
        void (async () => {
          try {
            ready ??= load().catch((error: unknown) => {
              ready = undefined;
              throw error;
            });
            const rp = await ready;
            const sid = sessionId(req, res);
            if (req.url === '/users') {
              send(res, 200, rp.list());
              return;
            }
            const body = await readBody(req);
            switch (req.url) {
              case '/credentials/remove':
                send(res, 200, rp.removeCredentials(body));
                return;
              case '/register/options':
                send(res, 200, await rp.registrationOptions(sid, body));
                return;
              case '/register/verify':
                send(res, 200, await rp.registrationVerify(sid, body));
                return;
              case '/authenticate/options':
                send(res, 200, await rp.authenticationOptions(sid, body));
                return;
              case '/authenticate/verify':
                send(res, 200, await rp.authenticationVerify(sid, body));
                return;
              default:
                send(res, 404, { message: 'Not found' });
            }
          } catch (error) {
            const status = error instanceof HttpError ? error.status : 400;
            const code =
              typeof error === 'object' && error !== null && 'code' in error
                ? String(error.code)
                : undefined;
            const message = error instanceof Error ? error.message : 'Request failed';
            send(res, status, { message: code ? `${code}: ${message}` : message, code });
          }
        })();
      });
    },
  };
}

export default defineConfig({
  root: fromRoot('./demo'),
  server: { host: RP_ID, port: PORT, strictPort: true },
  resolve: {
    // Exact-match regexes: a plain '@types' string alias would also capture '@types/node'.
    alias: [
      { find: /^@apps$/, replacement: fromRoot('./src/apps/index.ts') },
      { find: /^@libs$/, replacement: fromRoot('./src/libs/index.ts') },
      { find: /^@types$/, replacement: fromRoot('./src/types/index.ts') },
      { find: /^@utils$/, replacement: fromRoot('./src/utils/index.ts') },
      {
        find: '@xkid1/webauthn/client',
        replacement: fromRoot('./src/apps/client-side/index.ts'),
      },
    ],
  },
  plugins: [demoRelyingParty()],
});

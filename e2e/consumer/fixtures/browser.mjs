/**
 * Installs just enough of a browser (`navigator.credentials`, `PublicKeyCredential`,
 * `isSecureContext`) on globalThis for `@xkid1/webauthn/client` to run in Node.
 * Credentials come from the SoftAuthenticator, converted to the binary shapes a
 * real browser returns (ArrayBuffers, getTransports(), …).
 */
const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const buffer = (text) => {
  const bytes = Buffer.from(text, 'base64url');
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
};

const GLOBALS = ['navigator', 'PublicKeyCredential', 'isSecureContext'];

/**
 * @param {import('./authenticator.mjs').SoftAuthenticator} authenticator
 * @param {{ origin: string }} context the page origin the "browser" reports
 * @returns {() => void} restore the original globals
 */
export function installBrowser(authenticator, { origin }) {
  const saved = GLOBALS.map((name) => [
    name,
    Object.getOwnPropertyDescriptor(globalThis, name),
  ]);

  const credentials = {
    async create({ publicKey }) {
      const json = authenticator.register(
        {
          ...publicKey,
          challenge: b64url(publicKey.challenge),
          user: { ...publicKey.user, id: b64url(publicKey.user.id) },
        },
        { origin },
      );
      return {
        id: json.id,
        rawId: buffer(json.rawId),
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: buffer(json.response.clientDataJSON),
          attestationObject: buffer(json.response.attestationObject),
          getTransports: () => json.response.transports,
          getPublicKeyAlgorithm: () => json.response.publicKeyAlgorithm,
        },
        getClientExtensionResults: () => ({ credProps: { rk: true } }),
      };
    },
    async get({ publicKey }) {
      const json = authenticator.authenticate(
        { ...publicKey, challenge: b64url(publicKey.challenge) },
        { origin },
      );
      return {
        id: json.id,
        rawId: buffer(json.rawId),
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: buffer(json.response.clientDataJSON),
          authenticatorData: buffer(json.response.authenticatorData),
          signature: buffer(json.response.signature),
          userHandle: json.response.userHandle ? buffer(json.response.userHandle) : null,
        },
        getClientExtensionResults: () => ({}),
      };
    },
  };

  const define = (name, value) =>
    Object.defineProperty(globalThis, name, {
      value,
      configurable: true,
      writable: true,
    });
  define('navigator', { credentials });
  define('PublicKeyCredential', {
    isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
    isConditionalMediationAvailable: async () => true,
  });
  define('isSecureContext', true);

  return () => {
    for (const [name, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  };
}

/**
 * Advanced settings panel. The values are sent to the demo relying party, which
 * allowlists them and uses them to build the WebAuthn options.
 */

export interface DemoSettings {
  readonly registration: {
    readonly userVerification: string;
    readonly attachment: string;
    readonly residentKey: string;
    readonly attestation: string;
    readonly algorithms: readonly number[];
    readonly hints: readonly string[];
  };
  readonly authentication: {
    readonly userVerification: string;
    readonly hints: readonly string[];
  };
}

interface Choice<T> {
  readonly value: T;
  readonly label: string;
}

const ALGORITHMS: readonly Choice<number>[] = [
  { value: -8, label: 'EdDSA' },
  { value: -19, label: 'Ed25519' },
  { value: -7, label: 'ES256' },
  { value: -35, label: 'ES384' },
  { value: -36, label: 'ES512' },
  { value: -37, label: 'PS256' },
  { value: -257, label: 'RS256' },
];

const HINTS: readonly Choice<string>[] = [
  { value: 'security-key', label: 'Security Key' },
  { value: 'client-device', label: 'Client Device' },
  { value: 'hybrid', label: 'Hybrid' },
];

const DEFAULTS: DemoSettings = {
  registration: {
    userVerification: 'preferred',
    attachment: 'all',
    residentKey: 'preferred',
    attestation: 'none',
    algorithms: [-8, -7, -257],
    hints: [],
  },
  authentication: { userVerification: 'preferred', hints: [] },
};

const STORAGE_KEY = 'webauthn-demo-settings';

function load(): DemoSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULTS;
    const saved = JSON.parse(raw) as Partial<DemoSettings>;
    return {
      registration: { ...DEFAULTS.registration, ...saved.registration },
      authentication: { ...DEFAULTS.authentication, ...saved.authentication },
    };
  } catch {
    return DEFAULTS;
  }
}

function save(settings: DemoSettings): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // Storage unavailable (private mode…): settings just won't persist.
  }
}

/**
 * A group of checkboxes whose order is the order they were ticked
 * ("most to least preferred"), shown underneath as `Order: [...]`.
 */
function orderedCheckboxes<T extends string | number>(
  container: HTMLElement,
  name: string,
  choices: readonly Choice<T>[],
  initial: readonly T[],
  onChange: () => void,
): () => T[] {
  let order = initial.filter((v) => choices.some((c) => c.value === v));
  const boxes = document.createElement('div');
  boxes.className = 'checks';
  const orderText = document.createElement('div');
  orderText.className = 'order';
  const labelOf = (v: T) => choices.find((c) => c.value === v)?.label ?? String(v);
  const renderOrder = () => {
    orderText.textContent = `Order: [${order.map((v) => `"${labelOf(v).toLowerCase()}"`).join(', ')}]`;
  };

  for (const choice of choices) {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.name = name;
    input.checked = order.includes(choice.value);
    input.addEventListener('change', () => {
      order = input.checked
        ? [...order, choice.value]
        : order.filter((v) => v !== choice.value);
      renderOrder();
      onChange();
    });
    label.append(input, ` ${choice.label}`);
    boxes.append(label);
  }
  renderOrder();
  container.replaceChildren(boxes, orderText);
  return () => [...order];
}

/** Wire up the panel in `index.html`; returns a getter for the current settings. */
export function setupSettings(): () => DemoSettings {
  const initial = load();
  const select = (id: string, value: string): HTMLSelectElement => {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLSelectElement)) throw new Error(`#${id} missing`);
    el.value = value;
    el.addEventListener('change', persist);
    return el;
  };
  const container = (id: string): HTMLElement => {
    const el = document.getElementById(id);
    if (!el) throw new Error(`#${id} missing`);
    return el;
  };

  const regUv = select('reg-uv', initial.registration.userVerification);
  const regAttachment = select('reg-attachment', initial.registration.attachment);
  const regResidentKey = select('reg-resident-key', initial.registration.residentKey);
  const regAttestation = select('reg-attestation', initial.registration.attestation);
  const authUv = select('auth-uv', initial.authentication.userVerification);

  const regAlgorithms = orderedCheckboxes(
    container('reg-algorithms'),
    'reg-algorithms',
    ALGORITHMS,
    initial.registration.algorithms,
    persist,
  );
  const regHints = orderedCheckboxes(
    container('reg-hints'),
    'reg-hints',
    HINTS,
    initial.registration.hints,
    persist,
  );
  const authHints = orderedCheckboxes(
    container('auth-hints'),
    'auth-hints',
    HINTS,
    initial.authentication.hints,
    persist,
  );

  function current(): DemoSettings {
    return {
      registration: {
        userVerification: regUv.value,
        attachment: regAttachment.value,
        residentKey: regResidentKey.value,
        attestation: regAttestation.value,
        algorithms: regAlgorithms(),
        hints: regHints(),
      },
      authentication: { userVerification: authUv.value, hints: authHints() },
    };
  }

  function persist(): void {
    save(current());
  }

  document.getElementById('reset-settings')?.addEventListener('click', () => {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
    location.reload();
  });

  return current;
}

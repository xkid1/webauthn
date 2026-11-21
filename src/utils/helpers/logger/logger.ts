import type {
  ConsoleGlobal,
  LogLevel,
  ProcessGlobal,
  ProcessLike,
  WritableLevel,
} from '@types';

const LEVEL_WEIGHT: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

const COLORS: Record<WritableLevel, string> = {
  debug: '\x1b[90m', // gray
  info: '\x1b[36m', // cyan
  warn: '\x1b[33m', // yellow
  error: '\x1b[31m', // red
};
const RESET = '\x1b[0m';

/** `process` when running in Node/Electron main, `undefined` in browsers and WebViews. */
function getProcess(): ProcessLike | undefined {
  const candidate = (globalThis as ProcessGlobal).process;
  return typeof candidate === 'object' ? candidate : undefined;
}

export function isLogLevel(value: unknown): value is LogLevel {
  return typeof value === 'string' && Object.hasOwn(LEVEL_WEIGHT, value);
}

/**
 * Tiny leveled console logger with namespaces. Works in Node, browsers, Electron and WebViews.
 *
 * - Level: `Logger.setLevel()` → `process.env.LOG_LEVEL` (Node only) → `info`.
 * - ANSI colours only on a Node TTY without `NO_COLOR`; browsers get plain prefixes.
 * - `child('db')` creates the namespace `parent:db`.
 *
 * ```ts
 * const log = new Logger('tour-guide');
 * log.warn('Unknown option', key);   // 2026-01-01T00:00:00.000Z WARN  [tour-guide] Unknown option …
 * ```
 */
export class Logger {
  static #levelOverride: LogLevel | null = null;

  readonly #namespace: string;

  constructor(namespace: string) {
    this.#namespace = namespace;
  }

  /** Sets the level for every logger. Takes priority over `LOG_LEVEL`. */
  static setLevel(level: LogLevel): void {
    Logger.#levelOverride = level;
  }

  /** Effective level: `setLevel()` override, then `LOG_LEVEL`, then `info`. */
  static getLevel(): LogLevel {
    if (Logger.#levelOverride) return Logger.#levelOverride;
    const fromEnv = getProcess()?.env?.LOG_LEVEL?.toLowerCase();
    return isLogLevel(fromEnv) ? fromEnv : 'info';
  }

  get namespace(): string {
    return this.#namespace;
  }

  child(subNamespace: string): Logger {
    return new Logger(`${this.#namespace}:${subNamespace}`);
  }

  debug(message: unknown, ...args: unknown[]): void {
    this.#write('debug', message, args);
  }

  info(message: unknown, ...args: unknown[]): void {
    this.#write('info', message, args);
  }

  warn(message: unknown, ...args: unknown[]): void {
    this.#write('warn', message, args);
  }

  /** Error objects are printed with their stack trace by the console. */
  error(message: unknown, ...args: unknown[]): void {
    this.#write('error', message, args);
  }

  #prefix(level: WritableLevel): string {
    const proc = getProcess();
    const useColor = proc?.stdout?.isTTY === true && !proc.env?.NO_COLOR;
    const time = new Date().toISOString();
    const tag = level.toUpperCase().padEnd(5);
    return useColor
      ? `${COLORS[level]}${time} ${tag}${RESET} [${this.#namespace}]`
      : `${time} ${tag} [${this.#namespace}]`;
  }

  #write(level: WritableLevel, message: unknown, args: unknown[]): void {
    if (LEVEL_WEIGHT[level] < LEVEL_WEIGHT[Logger.getLevel()]) return;
    const method = level === 'info' ? 'log' : level;
    // Read through globalThis: the published build has no DOM or Node lib types.
    (globalThis as ConsoleGlobal).console?.[method](
      this.#prefix(level),
      message,
      ...args,
    );
  }
}

/** The library's own logger. Silence it with `setLogLevel('silent')`. */
export const logger = new Logger('tour-guide');

/** Sets how much `<tour-guide>` logs: `debug`, `info` (default), `warn`, `error`, `silent`. */
export function setLogLevel(level: LogLevel): void {
  Logger.setLevel(level);
}

export default Logger;

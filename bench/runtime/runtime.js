/** Runtime detection and CLI args without depending on `process` (absent in Deno and browsers). */

/** @typedef {{ name: string, version: string }} RuntimeInfo */

/** @returns {RuntimeInfo} */
export function detectRuntime() {
  const g = /** @type {any} */ (globalThis);
  if (g.Deno) return { name: 'deno', version: g.Deno.version.deno };
  if (g.Bun) return { name: 'bun', version: g.Bun.version };
  if (g.process?.versions?.node)
    return { name: 'node', version: g.process.versions.node };
  return { name: 'browser', version: g.navigator?.userAgent ?? 'unknown' };
}

/** @returns {string[]} */
export function cliArgs() {
  const g = /** @type {any} */ (globalThis);
  if (g.Deno) return [...g.Deno.args];
  return g.process ? g.process.argv.slice(2) : [];
}

export const RESULT_MARKER = '@@BENCH_RESULT@@';

/** Print a machine-readable result line for the orchestrator. @param {unknown} value */
export function emit(value) {
  console.log(`${RESULT_MARKER}${JSON.stringify(value)}`);
}

// Shared helpers for the benchmark scripts (Markdown tables, formatting).
import { readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Render a Markdown table; the first column is left-aligned, the rest right-aligned.
 * @param {string[]} headers
 * @param {string[][]} rows
 * @returns {string}
 */
export function table(headers, rows) {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)),
  );
  /** @param {string[]} cells */
  const line = (cells) =>
    `| ${cells.map((c, i) => (i === 0 ? c.padEnd(widths[i] ?? 0) : c.padStart(widths[i] ?? 0))).join(' | ')} |`;
  const rule = `|${widths.map((w, i) => (i === 0 ? '-'.repeat(w + 2) : `${'-'.repeat(w + 1)}:`)).join('|')}|`;
  return [line(headers), rule, ...rows.map(line)].join('\n');
}

/** @param {number} bytes */
export const kb = (bytes) => `${(bytes / 1024).toFixed(2)} kB`;

/** @param {number} hz */
export const fmtHz = (hz) =>
  hz >= 100 ? Math.round(hz).toLocaleString('en-US') : hz.toFixed(1);

/** @param {number[]} xs */
export function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? (s[m] ?? 0) : ((s[m - 1] ?? 0) + (s[m] ?? 0)) / 2;
}

/**
 * All files below `dir`, recursively.
 * @param {string} dir
 * @returns {string[]}
 */
export function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((d) =>
    d.isDirectory() ? walk(join(dir, d.name)) : [join(dir, d.name)],
  );
}

/**
 * Parse `--key=value` / `--flag` CLI arguments.
 * @param {string[]} argv
 * @returns {Record<string, string>}
 */
export function parseArgs(argv) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const arg of argv) {
    const [key = '', value = 'true'] = arg.replace(/^--/u, '').split('=');
    out[key] = value;
  }
  return out;
}

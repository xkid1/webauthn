// Rewrites layer aliases (@apps, @libs, @types, @utils) in dist/**/*.{js,d.ts}
// into relative specifiers so the published package runs without any resolver.
// Zero-dependency replacement for tsc-alias.
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const distDir = fileURLToPath(new URL('../dist', import.meta.url));

/** Alias -> barrel path inside dist (without extension). @type {Record<string, string>} */
const ALIASES = {
  '@apps': 'apps/index',
  '@libs': 'libs/index',
  '@types': 'types/index',
  '@utils': 'utils/index',
};

const SPECIFIER =
  /(\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(['"])(@apps|@libs|@types|@utils)\2/g;

/** @param {string} dir @returns {string[]} */
function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

/** @param {string} file @param {string} alias */
function toRelative(file, alias) {
  const target = join(distDir, `${ALIASES[alias]}.js`);
  let rel = relative(dirname(file), target).split(sep).join('/');
  if (!rel.startsWith('.')) rel = `./${rel}`;
  return rel;
}

let rewritten = 0;
for (const file of walk(distDir)) {
  if (!file.endsWith('.js') && !file.endsWith('.d.ts')) continue;
  const source = readFileSync(file, 'utf8');
  const next = source.replace(SPECIFIER, (_m, prefix, quote, alias) => {
    rewritten += 1;
    return `${prefix}${quote}${toRelative(file, alias)}${quote}`;
  });
  if (next !== source) writeFileSync(file, next);
}

console.log(`rewrite-aliases: rewrote ${rewritten} specifier(s) in dist/`);

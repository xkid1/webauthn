// Post-processes dist/**/*.{js,d.ts} so the published package runs without any resolver:
//   1. layer aliases (@apps, @libs, @types, @utils) become relative specifiers;
//   2. extensionless relative specifiers ('./decoder', '../config/index') get the explicit
//      '.js' (or '/index.js') that Node ESM and `moduleResolution: nodenext` require.
// Source files in src/ import without extensions; this is where they are made fully specified.
// Zero-dependency replacement for tsc-alias.
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const distDir = fileURLToPath(new URL('../dist', import.meta.url));

/** Alias -> barrel path inside dist (without extension). @type {Record<string, string>} */
const ALIASES = {
  '@apps': 'apps/index',
  '@libs': 'libs/index',
  '@types': 'types/index',
  '@utils': 'utils/index',
};

const ALIAS_SPECIFIER =
  /(\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(['"])(@apps|@libs|@types|@utils)\2/g;

const RELATIVE_SPECIFIER =
  /(\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(['"])(\.{1,2}\/[^'"\n]*)\2/g;

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

/**
 * Adds the missing extension to a relative specifier, checked against what exists in dist/.
 * @param {string} file @param {string} spec @returns {string | undefined}
 */
function toFullySpecified(file, spec) {
  if (/\.(?:js|mjs|cjs|json)$/.test(spec)) return undefined;
  const base = resolve(dirname(file), spec);
  const ext = file.endsWith('.d.ts') ? '.d.ts' : '.js';
  if (existsSync(`${base}${ext}`)) return `${spec}.js`;
  if (existsSync(join(base, `index${ext}`))) return `${spec.replace(/\/$/, '')}/index.js`;
  throw new Error(
    `rewrite-aliases: cannot resolve '${spec}' from ${relative(distDir, file)}`,
  );
}

let aliases = 0;
let extensions = 0;
for (const file of walk(distDir)) {
  if (!file.endsWith('.js') && !file.endsWith('.d.ts')) continue;
  const source = readFileSync(file, 'utf8');
  const next = source
    .replace(ALIAS_SPECIFIER, (_m, prefix, quote, alias) => {
      aliases += 1;
      return `${prefix}${quote}${toRelative(file, alias)}${quote}`;
    })
    .replace(RELATIVE_SPECIFIER, (match, prefix, quote, spec) => {
      const full = toFullySpecified(file, spec);
      if (full === undefined) return match;
      extensions += 1;
      return `${prefix}${quote}${full}${quote}`;
    });
  if (next !== source) writeFileSync(file, next);
}

console.log(
  `rewrite-aliases: rewrote ${aliases} alias(es) and completed ${extensions} extension(s) in dist/`,
);

// Sanity checks for the published build:
//  1. no unresolved layer aliases remain
//  2. no bare (package) imports => zero runtime dependencies
//  3. every relative import points at an existing file
//  4. every public entry point loads in Node
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const distDir = join(root, 'dist');
const IMPORT = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(['"])([^'"]+)\1/g;

/** @param {string} dir @returns {string[]} */
const walk = (dir) =>
  readdirSync(dir).flatMap((n) => {
    const f = join(dir, n);
    return statSync(f).isDirectory() ? walk(f) : [f];
  });

/** Drop block and line comments so examples in JSDoc are not treated as imports. */
/** @param {string} code */
const stripComments = (code) =>
  code.replace(/\/\*[\s\S]*?\*\//gu, '').replace(/^\s*\/\/.*$/gmu, '');

const problems = [];
for (const file of walk(distDir)) {
  if (!file.endsWith('.js') && !file.endsWith('.d.ts')) continue;
  for (const match of stripComments(readFileSync(file, 'utf8')).matchAll(IMPORT)) {
    const spec = match[2] ?? '';
    if (
      spec.startsWith('@apps') ||
      spec.startsWith('@libs') ||
      spec.startsWith('@utils') ||
      spec === '@types'
    ) {
      problems.push(`${file}: unresolved alias "${spec}"`);
    } else if (!spec.startsWith('.')) {
      problems.push(`${file}: bare import "${spec}" (package must stay zero-dependency)`);
    } else if (!existsSync(resolve(dirname(file), spec))) {
      problems.push(`${file}: missing target "${spec}"`);
    }
  }
}

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
if (pkg.dependencies && Object.keys(pkg.dependencies).length > 0) {
  problems.push('package.json declares runtime dependencies');
}
for (const [subpath, target] of Object.entries(pkg.exports)) {
  if (typeof target === 'string') continue;
  for (const key of ['types', 'import']) {
    if (!existsSync(join(root, target[key])))
      problems.push(`exports["${subpath}"].${key} missing`);
  }
  try {
    await import(pathToFileURL(join(root, target.import)).href);
  } catch (error) {
    problems.push(`exports["${subpath}"] failed to load: ${String(error)}`);
  }
}

if (problems.length > 0) {
  console.error(problems.join('\n'));
  process.exitCode = 1;
} else {
  console.log('verify-dist: OK');
}

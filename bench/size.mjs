#!/usr/bin/env node
// Size report for the BUILT package (dist/).
//
//   1. Install size – the npm tarball, unpacked size, file count, JS-only bytes
//   2. Bundle size  – what each use case adds to an app after tree-shaking:
//                     bundled + minified with Rolldown, then gzip and brotli
//
// `--check` fails when a bundle exceeds its brotli budget in bench/size-budget.json.
// Usage: yarn build && node bench/size.mjs [--check] [--json=size.json]
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';

import { build } from 'rolldown';

import { kb, parseArgs, table, walk } from './report.mjs';

/**
 * @typedef {{ name: string, code: string }} UseCase
 * @typedef {{ name: string, minified: number, gzip: number, brotli: number }} BundleSize
 * @typedef {{ tarball: number, unpacked: number, files: number, js: number, dts: number, maps: number }} InstallSize
 */

const root = fileURLToPath(new URL('..', import.meta.url));
const dist = join(root, 'dist');
const args = parseArgs(process.argv.slice(2));

/** @type {{ exports: Record<string, string | { import: string }>, dependencies?: Record<string, string> }} */
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

/** @param {string} subpath */
function entry(subpath) {
  const target = pkg.exports[subpath];
  if (!target || typeof target === 'string')
    throw new Error(`no import target for "${subpath}"`);
  return join(root, target.import);
}

/** Realistic imports, from "everything" down to typical single-purpose usage. @type {UseCase[]} */
const CASES = [
  { name: 'everything (import * from root)', code: `export * from '${entry('.')}';` },
  { name: 'client: entire entry point', code: `export * from '${entry('./client')}';` },
  {
    name: 'client: startRegistration + startAuthentication',
    code: `export { startRegistration, startAuthentication } from '${entry('./client')}';`,
  },
  {
    name: 'client: createWebAuthnClient',
    code: `export { createWebAuthnClient } from '${entry('./client')}';`,
  },
  {
    name: 'client: isWebAuthnSupported',
    code: `export { isWebAuthnSupported } from '${entry('./client')}';`,
  },
  { name: 'server: entire entry point', code: `export * from '${entry('./server')}';` },
  {
    name: 'server: createWebAuthnServer + MemoryChallengeStore',
    code: `export { createWebAuthnServer, MemoryChallengeStore } from '${entry('./server')}';`,
  },
  { name: 'android: entire entry point', code: `export * from '${entry('./android')}';` },
  {
    name: 'android: createAndroidPasskeyClient',
    code: `export { createAndroidPasskeyClient } from '${entry('./android')}';`,
  },
];

/**
 * @param {string} work temp directory
 * @returns {InstallSize}
 */
function installSize(work) {
  const tarball = join(work, 'package.tgz');
  const res = spawnSync('yarn', ['pack', '--out', tarball], {
    cwd: root,
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
  if (res.status !== 0) throw new Error(`yarn pack failed:\n${res.stdout}${res.stderr}`);

  const files = [
    ...walk(dist),
    ...['package.json', 'README.md', 'LICENSE'].map((f) => join(root, f)),
  ].filter((f) => existsSync(f));
  /** @param {(file: string) => boolean} filter */
  const bytes = (filter) =>
    files.filter(filter).reduce((n, f) => n + statSync(f).size, 0);
  return {
    tarball: statSync(tarball).size,
    unpacked: bytes(() => true),
    files: files.length,
    js: bytes((f) => f.endsWith('.js')),
    dts: bytes((f) => f.endsWith('.d.ts')),
    maps: bytes((f) => f.endsWith('.map')),
  };
}

/**
 * @param {string} work
 * @param {UseCase} useCase
 * @param {number} index
 * @returns {Promise<BundleSize>}
 */
async function bundleSize(work, useCase, index) {
  const input = join(work, `case-${index}.js`);
  writeFileSync(input, `${useCase.code}\n`);
  const { output } = await build({
    input,
    write: false,
    platform: 'neutral',
    treeshake: true,
    logLevel: 'silent',
    output: { format: 'esm', minify: true },
  });
  const code = Buffer.from(
    output.map((o) => (o.type === 'chunk' ? o.code : '')).join('\n'),
  );
  return {
    name: useCase.name,
    minified: code.length,
    gzip: gzipSync(code, { level: 9 }).length,
    brotli: brotliCompressSync(code, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } })
      .length,
  };
}

async function main() {
  const work = mkdtempSync(join(tmpdir(), 'webauthn-size-'));
  try {
    const install = installSize(work);
    console.log('\nInstall size (what `npm install @xkid1/webauthn` downloads)\n');
    console.log(
      table(
        ['metric', 'size'],
        [
          ['tarball (.tgz)', kb(install.tarball)],
          ['unpacked', kb(install.unpacked)],
          ['  JavaScript', kb(install.js)],
          ['  type declarations (.d.ts)', kb(install.dts)],
          ['  source maps', kb(install.maps)],
          ['files', String(install.files)],
          ['dependencies', String(Object.keys(pkg.dependencies ?? {}).length)],
        ],
      ),
    );

    /** @type {BundleSize[]} */
    const bundles = [];
    for (const [i, useCase] of CASES.entries())
      bundles.push(await bundleSize(work, useCase, i));

    /** @type {Record<string, number>} */
    const budgets = JSON.parse(
      readFileSync(new URL('./size-budget.json', import.meta.url), 'utf8'),
    );
    /** @type {BundleSize[]} */
    const over = [];
    console.log(
      '\nBundle size (tree-shaken + minified with Rolldown; what your users download)\n',
    );
    console.log(
      table(
        ['import', 'minified', 'gzip', 'brotli', 'budget (brotli)'],
        bundles.map((b) => {
          const budget = budgets[b.name];
          let status = '–';
          if (budget !== undefined) {
            status = `${b.brotli <= budget ? '✔' : '✘'} ${kb(budget)}`;
            if (b.brotli > budget) over.push(b);
          }
          return [b.name, kb(b.minified), kb(b.gzip), kb(b.brotli), status];
        }),
      ),
    );

    if (args.json) {
      writeFileSync(
        args.json,
        `${JSON.stringify({ date: new Date().toISOString(), install, bundles }, null, 2)}\n`,
      );
      console.log(`\nWrote ${args.json}`);
    }
    if (args.check && over.length > 0) {
      console.error(
        `\n✘ ${over.length} bundle(s) exceed the size budget in bench/size-budget.json`,
      );
      process.exitCode = 1;
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

if (existsSync(join(dist, 'index.js'))) {
  await main();
} else {
  console.error('dist/ not found – run `yarn build` first.');
  process.exitCode = 1;
}

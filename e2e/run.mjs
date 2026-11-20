#!/usr/bin/env node
// End-to-end test of the PUBLISHED package, as an application developer gets it:
//
//   1. `yarn pack` the built package (only what "files" publishes)
//   2. create a fresh consumer project in a temp directory
//   3. `npm install --offline <tarball>`: succeeds only with zero dependencies
//   4. run the consumer's JavaScript tests with `node --test`
//   5. type-check a TypeScript consumer (NodeNext + Bundler resolution, skipLibCheck off)
//
// Usage: yarn build && node e2e/run.mjs [--keep]
import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const consumerSource = fileURLToPath(new URL('./consumer/', import.meta.url));
const keep = process.argv.includes('--keep');
const shell = process.platform === 'win32';

function run(label, command, args, cwd) {
  console.log(`\n▶ ${label}\n  $ ${[command, ...args].join(' ')}`);
  const result = spawnSync(command, args, { cwd, stdio: 'inherit', shell });
  if (result.status !== 0) {
    throw new Error(`${label} failed (exit ${result.status ?? result.signal})`);
  }
}

function main() {
  if (!existsSync(join(root, 'dist', 'index.js'))) {
    throw new Error('dist/ not found – run `yarn build` first.');
  }
  return mkdtempSync(join(tmpdir(), 'webauthn-e2e-'));
}

let workdir;
let failed = false;
try {
  workdir = main();
  const tarball = join(workdir, 'xkid1-webauthn.tgz');
  run('Pack the published files', 'yarn', ['pack', '--out', tarball], root);

  const app = join(workdir, 'app');
  cpSync(consumerSource, app, { recursive: true });
  writeFileSync(
    join(app, 'package.json'),
    `${JSON.stringify({ name: 'webauthn-e2e-consumer', private: true, type: 'module' }, null, 2)}\n`,
  );

  run(
    'Install like an application (offline: proves zero dependencies)',
    'npm',
    ['install', '--offline', '--no-audit', '--no-fund', '--no-package-lock', tarball],
    app,
  );

  const tests = readdirSync(app).filter((f) => f.endsWith('.test.mjs'));
  run('Run consumer tests', process.execPath, ['--test', ...tests], app);

  const tsc = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
  for (const config of ['tsconfig.nodenext.json', 'tsconfig.bundler.json']) {
    run(
      `Type-check TypeScript consumer (${config})`,
      process.execPath,
      [tsc, '-p', config],
      app,
    );
  }

  console.log('\n✔ e2e: the published package works for consumers');
} catch (error) {
  failed = true;
  console.error(`\n✘ e2e: ${error.message}`);
} finally {
  if (workdir && (keep || failed)) console.log(`\nConsumer project kept at ${workdir}`);
  else if (workdir) rmSync(workdir, { recursive: true, force: true });
}
process.exitCode = failed ? 1 : 0;

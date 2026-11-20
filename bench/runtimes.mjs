#!/usr/bin/env node
// Cross-runtime benchmark of the BUILT package (dist/).
//
//   - speed:       bench/runtime/suite.js in Node, Bun, Deno and browsers (via Playwright)
//   - cold import: fresh process per run, median of N, for every package entry point
//
// Runtimes that are not installed are skipped (reported, not failed).
//
// Usage: yarn build && node bench/runtimes.mjs [--time=1000] [--import-runs=7]
//        [--runtimes=node,bun,deno,chromium,firefox,webkit] [--json=bench-results.json]
// Browsers need the `playwright` package; set PLAYWRIGHT_DIR to a folder whose
// node_modules contains it when it is not installed in this repo.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { fmtHz, median, parseArgs, table } from './report.mjs';

/**
 * @typedef {import('./runtime/harness.js').BenchResult} BenchResult
 * @typedef {{ name: string, version: string }} RuntimeInfo
 * @typedef {{ runtime: RuntimeInfo, results: BenchResult[], skipped: { name: string, reason: string }[], importMs?: number }} SpeedRun
 * @typedef {'node' | 'bun' | 'deno'} CliRuntime
 * @typedef {'chromium' | 'firefox' | 'webkit'} BrowserName
 * @typedef {{ launch(): Promise<{ newPage(): Promise<any>, version(): string, close(): Promise<void> }> }} BrowserType
 */

const root = fileURLToPath(new URL('..', import.meta.url));
const runtimeDir = join(root, 'bench', 'runtime');
const RESULT_MARKER = '@@BENCH_RESULT@@';

const args = parseArgs(process.argv.slice(2));
const timeMs = Number(args.time ?? 1000);
const importRuns = Number(args['import-runs'] ?? 7);
const wanted = args.runtimes?.split(',');
/** @param {string} name */
const want = (name) => !wanted || wanted.includes(name);

/** @param {CliRuntime} runtime @returns {[string, string[]]} */
function commandFor(runtime) {
  if (runtime === 'node') return [process.execPath, []];
  if (runtime === 'bun') return ['bun', []];
  return ['deno', ['run', '--allow-read', '--allow-env']];
}

/** @param {string} cmd */
function isInstalled(cmd) {
  return (
    spawnSync(cmd, ['--version'], {
      stdio: 'ignore',
      shell: process.platform === 'win32',
    }).status === 0
  );
}

/**
 * Run a child script in `runtime` and parse its result line.
 * @param {CliRuntime} runtime
 * @param {string} script
 * @param {string[]} scriptArgs
 * @returns {any}
 */
function runChild(runtime, script, scriptArgs) {
  const [cmd, pre] = commandFor(runtime);
  const res = spawnSync(cmd, [...pre, join(runtimeDir, script), ...scriptArgs], {
    cwd: root,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    maxBuffer: 16 * 1024 * 1024,
  });
  const line = res.stdout.split('\n').find((l) => l.startsWith(RESULT_MARKER));
  if (res.status !== 0 || !line) {
    throw new Error(`${runtime} ${script} failed:\n${res.stderr || res.stdout}`);
  }
  return JSON.parse(line.slice(RESULT_MARKER.length));
}

/** @returns {{ name: string, file: string }[]} */
function entryPoints() {
  /** @type {{ exports: Record<string, string | { import: string }> }} */
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  return Object.entries(pkg.exports).flatMap(([subpath, target]) =>
    typeof target === 'string'
      ? []
      : [
          {
            name:
              subpath === '.' ? '@xkid1/webauthn' : `@xkid1/webauthn${subpath.slice(1)}`,
            file: target.import.replace(/^\.\/dist\//u, ''),
          },
        ],
  );
}

/* ------------------------------ browsers ------------------------------ */

/** @returns {Promise<Record<BrowserName, BrowserType>> | undefined} */
function loadPlaywright() {
  for (const base of [process.env.PLAYWRIGHT_DIR, root]) {
    if (!base) continue;
    try {
      const require = createRequire(join(base, 'package.json'));
      return import(pathToFileURL(require.resolve('playwright')).href);
    } catch {
      // try the next location
    }
  }
  return undefined;
}

/** @type {Record<string, string>} */
const MIME = {
  '.js': 'text/javascript',
  '.html': 'text/html',
  '.map': 'application/json',
};

/**
 * Static server limited to dist/ and bench/runtime/. 127.0.0.1 is a secure
 * context, so WebCrypto is available to the page.
 * @returns {Promise<import('node:http').Server>}
 */
function serveRepo() {
  const allowed = [join(root, 'dist') + sep, runtimeDir + sep];
  const server = createServer((req, res) => {
    const pathname = decodeURIComponent(new URL(req.url ?? '/', 'http://x').pathname);
    const path = normalize(join(root, pathname));
    if (!allowed.some((dir) => path.startsWith(dir)) || !existsSync(path)) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[extname(path)] ?? 'application/octet-stream',
    });
    res.end(readFileSync(path));
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve(server);
    });
  });
}

/**
 * @param {Record<BrowserName, BrowserType>} playwright
 * @param {BrowserName[]} names
 * @returns {Promise<SpeedRun[]>}
 */
async function runBrowsers(playwright, names) {
  const server = await serveRepo();
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const url = `http://127.0.0.1:${port}/bench/runtime/browser.html?time=${timeMs}`;
  /** @type {SpeedRun[]} */
  const out = [];
  try {
    for (const name of names) {
      /** @type {Awaited<ReturnType<BrowserType['launch']>> | undefined} */
      let browser;
      try {
        browser = await playwright[name].launch();
        const page = await browser.newPage();
        await page.goto(url);
        await page.waitForFunction(
          () => /** @type {any} */ (globalThis).__BENCH_RESULT__,
          undefined,
          { timeout: 0 },
        );
        const result = await page.evaluate(
          () => /** @type {any} */ (globalThis).__BENCH_RESULT__,
        );
        if (result.error) throw new Error(result.error);
        out.push({ ...result, runtime: { name, version: browser.version() } });
        console.log(`  ✔ ${name} ${browser.version()}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.log(`  – ${name}: skipped (${message.split('\n')[0]})`);
      } finally {
        await browser?.close();
      }
    }
  } finally {
    server.close();
  }
  return out;
}

/* ------------------------------- main ------------------------------- */

async function main() {
  /** @type {CliRuntime[]} */
  const cliRuntimes = ['node', 'bun', 'deno'];
  const requested = cliRuntimes.filter(want);
  const available = requested.filter((r) => r === 'node' || isInstalled(r));
  for (const r of requested.filter((x) => !available.includes(x))) {
    console.log(`– ${r}: not installed, skipped`);
  }

  /** @type {SpeedRun[]} */
  const speed = [];
  /** @type {Record<string, Record<string, number>>} */
  const imports = {};
  for (const runtime of available) {
    console.log(`▶ ${runtime}: speed suite (${timeMs} ms per benchmark)`);
    speed.push(runChild(runtime, 'speed.js', [String(timeMs)]));
    console.log(`▶ ${runtime}: cold import ×${importRuns} per entry point`);
    /** @type {Record<string, number>} */
    const perEntry = {};
    for (const e of entryPoints()) {
      const samples = Array.from({ length: importRuns }, () =>
        Number(runChild(runtime, 'import-time.js', [e.file]).ms),
      );
      perEntry[e.name] = median(samples);
    }
    imports[runtime] = perEntry;
  }

  /** @type {BrowserName[]} */
  const browsers = ['chromium', 'firefox', 'webkit'];
  const requestedBrowsers = browsers.filter(want);
  if (requestedBrowsers.length > 0) {
    const playwright = await loadPlaywright();
    if (playwright) {
      console.log('▶ browsers (Playwright)');
      for (const result of await runBrowsers(playwright, requestedBrowsers)) {
        speed.push(result);
        if (result.importMs !== undefined) {
          imports[result.runtime.name] = { '@xkid1/webauthn': result.importMs };
        }
      }
    } else {
      console.log(
        '– browsers: `playwright` not found, skipped (see bench/runtimes.mjs header)',
      );
    }
  }

  const columns = speed.map(
    (s) => `${s.runtime.name} ${s.runtime.version.split(' ')[0] ?? ''}`,
  );
  const names = [...new Set(speed.flatMap((s) => s.results.map((r) => r.name)))];
  console.log('\nSpeed (operations / second, higher is better)\n');
  console.log(
    table(
      ['benchmark', ...columns],
      names.map((n) => [
        n,
        ...speed.map((s) => {
          const r = s.results.find((x) => x.name === n);
          return r ? `${fmtHz(r.hz)} ±${r.rme.toFixed(1)}%` : 'n/a';
        }),
      ]),
    ),
  );
  for (const s of speed) {
    for (const k of s.skipped)
      console.log(`  note (${s.runtime.name}): ${k.name} – ${k.reason}`);
  }

  const importRuntimes = Object.keys(imports);
  console.log(
    `\nCold import (ms, median of ${importRuns} fresh processes; browsers: one page load)\n`,
  );
  console.log(
    table(
      ['entry point', ...importRuntimes],
      entryPoints().map((e) => [
        e.name,
        ...importRuntimes.map((r) => {
          const ms = imports[r]?.[e.name];
          return ms === undefined ? '–' : ms.toFixed(2);
        }),
      ]),
    ),
  );

  if (args.json) {
    writeFileSync(
      args.json,
      `${JSON.stringify({ date: new Date().toISOString(), timeMs, speed, imports }, null, 2)}\n`,
    );
    console.log(`\nWrote ${args.json}`);
  }
}

if (existsSync(join(root, 'dist', 'index.js'))) {
  await main();
} else {
  console.error('dist/ not found – run `yarn build` first.');
  process.exitCode = 1;
}

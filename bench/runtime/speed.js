// Child process: run the speed suite in the current runtime against dist/.
// Usage: <node|bun|deno run --allow-read> bench/runtime/speed.js [timeMs]
import { cliArgs, detectRuntime, emit } from './runtime.js';
import { runSuite } from './suite.js';

const [time] = cliArgs();
const webauthn = await import(new URL('../../dist/index.js', import.meta.url).href);
const { results, skipped } = await runSuite(webauthn, { timeMs: Number(time ?? 1000) });
emit({ runtime: detectRuntime(), results, skipped });

// Child process: time a cold `import()` of one dist entry point (fresh process each run).
// Usage: <runtime> bench/runtime/import-time.js <dist-relative-path>
import { cliArgs, emit } from './runtime.js';

const [entry = 'index.js'] = cliArgs();
const url = new URL(`../../dist/${entry}`, import.meta.url).href;
const start = performance.now();
await import(url);
emit({ entry, ms: performance.now() - start });

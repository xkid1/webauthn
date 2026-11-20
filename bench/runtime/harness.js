/**
 * Tiny runtime-agnostic benchmark harness (performance.now only).
 *
 * Calls are timed in batches of ≥ MIN_BATCH_MS instead of one by one, so the
 * numbers stay meaningful where timers are coarsened (browsers clamp
 * performance.now() to 5 µs – 1 ms). Each batch mean is one sample.
 */

const MIN_BATCH_MS = 10;

/**
 * @typedef {object} BenchResult
 * @property {string} name
 * @property {number} hz       operations per second
 * @property {number} meanUs   mean time per operation (µs)
 * @property {number} rme      relative margin of error (%, 95% confidence)
 * @property {number} samples  number of batches
 * @property {number} ops      total operations measured
 */

/** @param {() => unknown} fn @param {number} n */
async function runBatch(fn, n) {
  const start = performance.now();
  for (let i = 0; i < n; i += 1) await fn();
  return performance.now() - start;
}

/**
 * @param {string} name
 * @param {() => unknown} fn  sync or async operation
 * @param {{ timeMs?: number, warmupMs?: number }} [options]
 * @returns {Promise<BenchResult>}
 */
export async function measure(name, fn, { timeMs = 1000, warmupMs = 200 } = {}) {
  // Warm up (JIT) and find a batch size that takes at least MIN_BATCH_MS.
  let batch = 1;
  const warmupEnd = performance.now() + warmupMs;
  while (performance.now() < warmupEnd || batch === 1) {
    const elapsed = await runBatch(fn, batch);
    if (elapsed < MIN_BATCH_MS) batch *= 2;
    else if (performance.now() >= warmupEnd) break;
  }

  /** @type {number[]} */
  const perOpMs = [];
  let ops = 0;
  const end = performance.now() + timeMs;
  while (performance.now() < end || perOpMs.length < 5) {
    const elapsed = await runBatch(fn, batch);
    perOpMs.push(elapsed / batch);
    ops += batch;
  }

  const mean = perOpMs.reduce((a, b) => a + b, 0) / perOpMs.length;
  const variance =
    perOpMs.reduce((a, b) => a + (b - mean) ** 2, 0) / Math.max(perOpMs.length - 1, 1);
  const sem = Math.sqrt(variance / perOpMs.length);
  return {
    name,
    hz: 1000 / mean,
    meanUs: mean * 1000,
    rme: mean > 0 ? ((1.96 * sem) / mean) * 100 : 0,
    samples: perOpMs.length,
    ops,
  };
}

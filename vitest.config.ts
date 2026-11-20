import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const fromRoot = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  resolve: {
    // Exact-match regexes: a plain '@types' string alias would also capture '@types/node'.
    alias: [
      { find: /^@apps$/, replacement: fromRoot('./src/apps/index.ts') },
      { find: /^@libs$/, replacement: fromRoot('./src/libs/index.ts') },
      { find: /^@types$/, replacement: fromRoot('./src/types/index.ts') },
      { find: /^@utils$/, replacement: fromRoot('./src/utils/index.ts') },
      { find: /^@tests$/, replacement: fromRoot('./tests/index.ts') },
    ],
  },
  test: {
    benchmark: {
      include: ['bench/**/*.bench.ts'],
    },
    include: ['src/**/*.test.ts'],
    environment: 'node',
    clearMocks: true,
    restoreMocks: true,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/index.ts', 'src/**/*.test.ts', 'src/types/**'],
      reporter: ['text', 'html', 'lcov'],
      thresholds: {
        lines: 85,
        functions: 85,
        branches: 75,
        statements: 85,
      },
    },
  },
});

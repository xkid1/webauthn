// Removes build output. Zero-dependency replacement for rimraf.
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

for (const dir of ['../dist', '../coverage']) {
  rmSync(fileURLToPath(new URL(dir, import.meta.url)), { recursive: true, force: true });
}

import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { CADDY_SECURITY_HEADERS } from '../src/csp';

const target = fileURLToPath(new URL('../../../docker/csp.caddy', import.meta.url));

await writeFile(target, CADDY_SECURITY_HEADERS, 'utf8');

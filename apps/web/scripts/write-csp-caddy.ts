import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { CADDY_SNIPPET_FILE, caddySecurityHeaders } from '../src/csp';

const target = fileURLToPath(new URL(`../../../docker/${CADDY_SNIPPET_FILE}`, import.meta.url));

await writeFile(target, caddySecurityHeaders(), 'utf8');

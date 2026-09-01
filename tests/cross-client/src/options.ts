/** What the orchestrator reads before it starts anything. `runAll.ts` runs on
 * import, so this is a module of its own. */

export const DEFAULT_WEB_PORT = 4175;
const MAX_PORT = 65535;

export const USAGE = `Usage: tsx src/runAll.ts [options]

The cross-client e2e suite: the built web bundle headless beside a mounted
desktop, against one stack. It needs Postgres, Kubo and the record store up, a
built API, a built web bundle carrying the e2e hook, and an "e2e-hook" build of
cipherbox-desktop. It starts and stops the API itself.

Options:
  --scenario <name>   Run only this scenario. Repeat for several.
  --list              List the scenario names and exit.
  --help              Show this text and exit.

Environment:
  CIPHERBOX_DESKTOP_BINARY   The e2e-hook build. Required.
  CIPHERBOX_API_ENTRY        The built API entry point.
                             Default: apps/api/dist/main.js
  CIPHERBOX_API_URL          Where the API answers.
                             Default: http://localhost:3000
  CIPHERBOX_WEB_DIST         The built web bundle, relative to apps/web.
                             Default: dist
  CIPHERBOX_WEB_PORT         Where this suite serves that bundle.
                             Default: ${DEFAULT_WEB_PORT}
  CIPHERBOX_E2E_WORKDIR      Home roots and logs, kept after a pass.
                             Default: a temporary directory the suite removes.
`;

/** The port this suite serves the bundle on. */
export function webPort(value: string | undefined): number {
  if (value === undefined || value === '') return DEFAULT_WEB_PORT;
  if (!/^[0-9]+$/.test(value)) throw new Error(`CIPHERBOX_WEB_PORT is not a number: ${value}`);
  const port = Number(value);
  if (port < 1 || port > MAX_PORT) {
    throw new Error(`CIPHERBOX_WEB_PORT ${port} is outside 1..${MAX_PORT}`);
  }
  return port;
}

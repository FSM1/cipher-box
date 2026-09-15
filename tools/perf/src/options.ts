/** The baseline runner's command line, apart from the entry point so the unit suite reads it. */

import { BASELINE_SCENARIOS, isBaselineScenario, type BaselineScenario } from './report';

export const USAGE = `\
usage: pnpm --filter @cipherbox/perf baseline -- --target <local|staging> [options]

options:
  --scenario <name>      one scenario, repeatable; the default is all five
  --clients <n>          concurrent accounts         (default 5)
  --ops-per-client <n>   iterations per account      (default 20)
  --report-dir <path>    where the JSON reports land (default load-reports)

Every other flag, bound and environment variable belongs to cipherbox-load;
run \`cargo run --release -p cipherbox-load -- --help\` for them.
`;

export interface Options {
  target: 'local' | 'staging';
  scenarios: BaselineScenario[];
  clients: string;
  opsPerClient: string;
  reportDir: string;
}

export function parseOptions(argv: readonly string[]): Options {
  const scenarios: BaselineScenario[] = [];
  let target = '';
  let clients = '5';
  let opsPerClient = '20';
  let reportDir = 'load-reports';

  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    // pnpm forwards the `--` separator into argv along with the flags after it.
    if (flag === '--') continue;
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`${flag} expects a value`);
    }
    i += 1;
    switch (flag) {
      case '--target':
        target = value;
        break;
      case '--scenario':
        if (!isBaselineScenario(value)) {
          throw new Error(
            `unknown scenario ${value}; the names are ${BASELINE_SCENARIOS.join(', ')}`
          );
        }
        scenarios.push(value);
        break;
      case '--clients':
        clients = value;
        break;
      case '--ops-per-client':
        opsPerClient = value;
        break;
      case '--report-dir':
        reportDir = value;
        break;
      default:
        throw new Error(`unknown flag ${flag}`);
    }
  }

  if (target !== 'local' && target !== 'staging') {
    throw new Error('--target must be local or staging');
  }
  return {
    target,
    scenarios: scenarios.length > 0 ? scenarios : [...BASELINE_SCENARIOS],
    clients,
    opsPerClient,
    reportDir,
  };
}

/**
 * The harness invocation for one scenario: an argument vector, never a shell
 * string, and never the login secret — that rides the inherited environment.
 */
export function command(
  options: Options,
  scenario: BaselineScenario,
  loadBinary: string | undefined
): { file: string; args: string[] } {
  const args = [
    '--scenario',
    scenario,
    '--target',
    options.target,
    '--clients',
    options.clients,
    '--ops-per-client',
    options.opsPerClient,
    '--report-dir',
    options.reportDir,
  ];
  if (loadBinary) return { file: loadBinary, args };
  return { file: 'cargo', args: ['run', '--release', '-p', 'cipherbox-load', '--', ...args] };
}

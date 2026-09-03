/**
 * Shared, so the mounted suite and the cross-client suite take one command line
 * and one run-bounding wait.
 */

export interface Options {
  help: boolean;
  list: boolean;
  only: string[];
}

export function parseArguments(argv: string[]): Options {
  const options: Options = { help: false, list: false, only: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const argument = argv[i];
    if (argument === '--help' || argument === '-h') options.help = true;
    else if (argument === '--list') options.list = true;
    else if (argument === '--scenario') {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('--scenario needs a scenario name. Run --list for the names.');
      }
      options.only.push(value);
      i += 1;
    } else {
      throw new Error(`unknown argument ${argument}. Run --help for the options.`);
    }
  }
  return options;
}

export function names(scenarios: readonly { name: string }[]): string[] {
  return scenarios.map((scenario) => scenario.name);
}

export function select<T extends { name: string }>(scenarios: readonly T[], options: Options): T[] {
  if (options.only.length === 0) return [...scenarios];
  return options.only.map((name) => {
    const found = scenarios.find((scenario) => scenario.name === name);
    if (!found) {
      throw new Error(
        `no scenario is named ${name}. The names are: ${names(scenarios).join(', ')}`
      );
    }
    return found;
  });
}

/**
 * Fails `body` when it outlasts the budget, and only after `release` settles.
 *
 * `release` is required: every orchestrator holds mounts, and a kernel call on
 * a mount has no timeout of its own. A rejection that lands first leaves those
 * calls holding the few filesystem threads Node has, and the teardown that
 * follows needs them.
 */
export function withDeadline<T>(
  body: Promise<T>,
  timeoutMs: number,
  what: string,
  release: () => Promise<unknown>
): Promise<T> {
  let fired = false;
  let timer: NodeJS.Timeout;
  const expiry = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      fired = true;
      void Promise.resolve()
        .then(release)
        .catch(() => undefined)
        .then(() => reject(new Error(`${what} did not finish within ${timeoutMs}ms`)));
    }, timeoutMs);
    timer.unref();
  });
  // Once the timer has fired the expiry is authoritative. A body that lands
  // while `release` still runs would otherwise hand the caller its teardown to
  // run beside the release, over the same mounts.
  return Promise.race([body, expiry])
    .then(
      (value) => (fired ? expiry : value),
      (error: unknown) => (fired ? expiry : Promise.reject(error))
    )
    .finally(() => clearTimeout(timer));
}

export function describe(error: unknown): string {
  return error instanceof Error ? (error.stack ?? error.message) : String(error);
}

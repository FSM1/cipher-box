/**
 * What every scenario gets, and the assertions they share.
 */

import type { Instance } from './instance';
import type { Deadlines } from './profile';
import type { Stack } from './stack';

export interface ScenarioContext {
  deadlines: Deadlines;
  /** The API, so a scenario can make a real outage. */
  stack: Stack;
  /** Starts a named instance on this scenario's own home root. */
  start(name: string): Promise<Instance>;
  log(message: string): void;
}

export interface Scenario {
  name: string;
  run(context: ScenarioContext): Promise<void>;
}

/**
 * Runs `body` with the named instances and stops every one of them, so a failed
 * scenario cannot strand a mount for the next one.
 */
export async function withInstances<T>(
  context: ScenarioContext,
  names: string[],
  body: (instances: Instance[]) => Promise<T>
): Promise<T> {
  const started: Instance[] = [];
  try {
    for (const name of names) started.push(await context.start(name));
    return await withDeadline(body(started), context.deadlines.scenarioMs);
  } finally {
    for (const instance of started.reverse()) await instance.stop();
  }
}

/**
 * Fails the scenario when its whole body outlasts the budget.
 *
 * A kernel call on a mount has no timeout of its own, so a mount that stops
 * answering hangs the process rather than the wait. The teardown that follows
 * unmounts, which is what releases the call.
 */
function withDeadline<T>(body: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout;
  const expiry = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`the scenario did not finish within ${timeoutMs}ms`)),
      timeoutMs
    );
    timer.unref();
  });
  return Promise.race([body, expiry]).finally(() => clearTimeout(timer));
}

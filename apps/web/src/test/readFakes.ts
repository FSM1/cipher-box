import type { EngineFacade } from '@cipherbox/client';

type ReadDescriptor = Parameters<EngineFacade['read']>[0];
type ReadKind = ReadDescriptor['kind'];

/** One stub per read kind, each handed the descriptor the facade was asked. */
export type ReadStubs = {
  [K in ReadKind]?: (read: Extract<ReadDescriptor, { kind: K }>) => Promise<unknown>;
};

/**
 * A facade `read` that answers each kind from its stub. A kind the test left
 * unstubbed is refused, so a surface reading more than the test expects fails
 * loudly instead of hanging.
 */
export function fakeRead(stubs: ReadStubs): EngineFacade['read'] {
  return ((read: ReadDescriptor) => {
    const stub = stubs[read.kind] as ((read: ReadDescriptor) => Promise<unknown>) | undefined;
    return stub === undefined
      ? Promise.reject(new Error(`no fake answers the ${read.kind} read`))
      : stub(read);
  }) as EngineFacade['read'];
}

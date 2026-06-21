import { EntityManager } from 'typeorm';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { IpfsProvider } from '../providers/ipfs-provider.interface';

/**
 * Acquires pg_advisory_xact_lock(hashtext(cid)::bigint) as the first
 * transactional statement and runs fn inside the lock.
 *
 * INT_MIN-safe: hashtext returns int4; casting directly to bigint sign-extends
 * the value rather than overflowing abs() on INT_MIN (-2147483648). DO NOT
 * add abs() before the cast — that was the bug fixed in Phase 42/50.
 */
export async function withCidLock<T>(
  manager: EntityManager,
  cid: string,
  fn: () => Promise<T>
): Promise<T> {
  await manager.query(`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, [cid]);
  return fn();
}

/**
 * Under an already-held CID advisory lock: recheck refcount, unpin when zero,
 * delete the outbox row.
 *
 * Must be called within a transaction that has already called withCidLock for
 * the same CID. Use only for drainRow (Kubo inside lock). Do NOT use at the
 * guardedUnpin post-commit site where Kubo must remain outside the transaction.
 */
export async function refcountAndMaybeUnpin(
  manager: EntityManager,
  cid: string,
  ipfsProvider: IpfsProvider
): Promise<void> {
  const refs = await manager.getRepository(PinnedCid).count({ where: { cid } });
  if (refs > 0) {
    await manager.getRepository(PendingUnpin).delete({ cid });
    return; // stale outbox row — CID is re-pinned
  }
  await ipfsProvider.unpinFile(cid);
  await manager.getRepository(PendingUnpin).delete({ cid });
}

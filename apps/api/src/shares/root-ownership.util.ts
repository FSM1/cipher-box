import { ForbiddenException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';

/**
 * D-01/SC#1 root-ownership gate (defense-in-depth, non-authoritative): reads the
 * ipns_records creator marker to reject callers who never registered this node.
 * The true access boundary is cryptographic (the sharer can only wrap keys they
 * hold) — this is a cheap anti-spoof check atop that boundary. Per D-02, only
 * shareRootIpnsName ownership is verified here; rootNodeId stays client-asserted.
 *
 * Shared by createShare (shares.service.ts) and createInvite
 * (share-invite.service.ts) — a single auditable authorization helper instead
 * of two drifting copies.
 */
export async function assertRootOwnership(
  ipnsRecordRepo: Repository<IpnsRecord>,
  ipnsName: string,
  userId: string
): Promise<void> {
  const owned = await ipnsRecordRepo.findOne({
    where: { ipnsName, userId },
  });
  if (!owned) {
    throw new ForbiddenException('You are not the registered owner of this node');
  }
}

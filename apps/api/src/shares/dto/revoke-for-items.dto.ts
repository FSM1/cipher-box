import { ApiProperty } from '@nestjs/swagger';
import {
  IsArray,
  ArrayNotEmpty,
  ArrayMaxSize,
  IsString,
  MaxLength,
  Matches,
} from 'class-validator';

/**
 * Bulk hard-revoke request: revoke every share/invite the authenticated user
 * created for ANY of the listed IPNS names. Used when an owner deletes an item
 * (file or folder) to the recycle bin — the client collects every node ipnsName
 * in the deleted subtree (the folder's own ipnsName + every descendant file's
 * fileMetaIpnsName + every descendant subfolder ipnsName) and sends them here so
 * the access cutoff happens BEFORE the eventual unpin orphans any sharee.
 *
 * The list may contain ipnsNames that were never shared — the endpoint revokes
 * whatever matches and no-ops the rest.
 */
export class RevokeForItemsDto {
  @ApiProperty({
    description:
      'IPNS names (k51...) of every node in the deleted subtree. Shares/invites ' +
      'the caller created for any of these are hard-revoked. Unshared names are ignored.',
    type: [String],
    example: ['k51qzi5uqu5dg...', 'k51qzi5uqu5dh...'],
  })
  @IsArray()
  @ArrayNotEmpty()
  // Bound the batch so a single request can't enumerate an unbounded subtree.
  // 5000 comfortably covers realistic vault subtrees while capping DB IN(...) size.
  @ArrayMaxSize(5000)
  @IsString({ each: true })
  @MaxLength(255, { each: true })
  // Defense-in-depth: reject malformed IPNS names early. Same CIDv1 libp2p-key
  // contract as the resolve/publish/unenroll DTOs — accepts k51 (base36) or
  // bafzaa (base32) forms.
  @Matches(/^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/, {
    each: true,
    message: 'each ipnsName must be a valid CIDv1 libp2p-key (k51qzi5uqu5... or bafzaa...)',
  })
  ipnsNames!: string[];
}

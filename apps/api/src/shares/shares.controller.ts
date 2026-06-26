import {
  Controller,
  Post,
  Get,
  Delete,
  Patch,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  ParseUUIDPipe,
  HttpCode,
  HttpStatus,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { BypassableThrottlerGuard as ThrottlerGuard } from '../common/guards/throttler-bypass.guard';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { SharesService } from './shares.service';
import { CreateShareDto } from './dto/create-share.dto';
import { AddShareKeysDto } from './dto/share-key.dto';
import { UpdateEncryptedKeyDto } from './dto/update-encrypted-key.dto';
import { UpdateItemNameDto } from './dto/update-item-name.dto';
import { UpdatePermissionDto } from './dto/update-permission.dto';
import { RevokeForItemsDto } from './dto/revoke-for-items.dto';
import {
  PaginationQueryDto,
  PaginatedReceivedSharesDto,
  PaginatedSentSharesDto,
} from './dto/pagination.dto';
import {
  CreateShareResponseDto,
  PendingRotationResponseDto,
  ShareKeyResponseDto,
  RevokeForItemsResponseDto,
} from './dto/share-response.dto';
import { LookupUserResponseDto } from './dto/lookup-user-response.dto';
import { RequestWithUser } from '../common/types';

@ApiTags('shares')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, ThrottlerGuard)
@Controller('shares')
export class SharesController {
  constructor(private readonly sharesService: SharesService) {}

  @Post()
  @ApiOperation({
    summary: 'Create a share',
    description:
      'Share an encrypted folder or file with another user. ' +
      'The encryptedKey is the item key re-wrapped for the recipient via ECIES.',
  })
  @ApiResponse({ status: 201, description: 'Share created', type: CreateShareResponseDto })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Recipient not found' })
  @ApiResponse({ status: 409, description: 'Share already exists or self-share' })
  async createShare(
    @Request() req: RequestWithUser,
    @Body() dto: CreateShareDto
  ): Promise<{
    shareId: string;
    itemType: string;
    ipnsName: string;
    itemName: string;
    itemNameEncrypted: string | null;
    encryptedKey: string;
    permission: string;
    createdAt: Date;
  }> {
    const share = await this.sharesService.createShare(req.user.id, dto);
    return {
      shareId: share.id,
      itemType: share.itemType,
      ipnsName: share.ipnsName,
      itemName: share.itemName,
      itemNameEncrypted: share.itemNameEncrypted ? share.itemNameEncrypted.toString('hex') : null,
      encryptedKey: share.encryptedKey.toString('hex'),
      permission: share.permission,
      createdAt: share.createdAt,
    };
  }

  @Post('revoke-for-items')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Bulk hard-revoke shares for deleted items',
    description:
      'Hard-revoke every share/invite the authenticated user created for any of ' +
      'the given IPNS names, atomically. Called when an owner deletes a file or ' +
      'folder subtree to the recycle bin so the access cutoff precedes the unpin. ' +
      'Shares are hard-deleted (keys cascade); active invites are marked revoked. ' +
      'IPNS names that were never shared are ignored.',
  })
  @ApiResponse({
    status: 200,
    description: 'Revocation summary',
    type: RevokeForItemsResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid request body' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async revokeForItems(
    @Request() req: RequestWithUser,
    @Body() dto: RevokeForItemsDto
  ): Promise<RevokeForItemsResponseDto> {
    return this.sharesService.revokeForItems(req.user.id, dto.ipnsNames);
  }

  @Get('received')
  @ApiOperation({
    summary: 'List received shares',
    description: 'Get active, non-hidden shares received by the authenticated user (paginated).',
  })
  @ApiResponse({
    status: 200,
    description: 'Paginated list of received shares',
    type: PaginatedReceivedSharesDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getReceivedShares(
    @Request() req: RequestWithUser,
    @Query() pagination: PaginationQueryDto
  ): Promise<PaginatedReceivedSharesDto> {
    const { shares, total } = await this.sharesService.getReceivedShares(
      req.user.id,
      pagination.limit,
      pagination.offset
    );
    return {
      shares: shares.map((s) => ({
        shareId: s.id,
        sharerPublicKey: s.sharer.publicKey,
        itemType: s.itemType,
        ipnsName: s.ipnsName,
        itemName: s.itemName,
        itemNameEncrypted: s.itemNameEncrypted ? s.itemNameEncrypted.toString('hex') : null,
        encryptedKey: s.encryptedKey.toString('hex'),
        permission: s.permission,
        encryptedIpnsKey: s.encryptedIpnsKey ? s.encryptedIpnsKey.toString('hex') : null,
        createdAt: s.createdAt,
      })),
      total,
    };
  }

  @Get('sent')
  @ApiOperation({
    summary: 'List sent shares',
    description: 'Get active shares created by the authenticated user (paginated).',
  })
  @ApiResponse({
    status: 200,
    description: 'Paginated list of sent shares',
    type: PaginatedSentSharesDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getSentShares(
    @Request() req: RequestWithUser,
    @Query() pagination: PaginationQueryDto
  ): Promise<PaginatedSentSharesDto> {
    const { shares, total } = await this.sharesService.getSentShares(
      req.user.id,
      pagination.limit,
      pagination.offset
    );
    return {
      shares: shares.map((s) => ({
        shareId: s.id,
        recipientPublicKey: s.recipient.publicKey,
        itemType: s.itemType,
        ipnsName: s.ipnsName,
        itemName: s.itemName,
        itemNameEncrypted: s.itemNameEncrypted ? s.itemNameEncrypted.toString('hex') : null,
        permission: s.permission,
        createdAt: s.createdAt,
      })),
      total,
    };
  }

  @Get('lookup')
  @ApiOperation({
    summary: 'Look up user by public key',
    description: 'Verify a public key belongs to a registered CipherBox user.',
  })
  @ApiQuery({
    name: 'publicKey',
    description: 'Uncompressed secp256k1 public key (0x04...)',
    required: true,
  })
  @ApiResponse({ status: 200, description: 'Lookup result', type: LookupUserResponseDto })
  @ApiResponse({ status: 400, description: 'Invalid public key format' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async lookupUser(@Query('publicKey') publicKey: string): Promise<LookupUserResponseDto> {
    if (!publicKey || !/^0x04[0-9a-fA-F]{128}$/.test(publicKey)) {
      throw new BadRequestException(
        'Invalid public key format. Expected uncompressed secp256k1 key: 0x04 + 128 hex chars'
      );
    }

    const exists = await this.sharesService.lookupUserByPublicKey(publicKey);
    return { exists };
  }

  @Get('pending-rotations')
  @ApiOperation({
    summary: 'Get pending rotations',
    description:
      'Get shares that have been revoked but not yet key-rotated. ' +
      'Used by the client to detect lazy rotation needs before folder modification.',
  })
  @ApiResponse({
    status: 200,
    description: 'List of revoked shares pending rotation',
    type: [PendingRotationResponseDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getPendingRotations(@Request() req: RequestWithUser): Promise<
    Array<{
      shareId: string;
      recipientPublicKey: string;
      itemType: string;
      ipnsName: string;
      itemName: string;
      revokedAt: Date;
    }>
  > {
    const shares = await this.sharesService.getPendingRotations(req.user.id);
    return shares.map((s) => ({
      shareId: s.id,
      recipientPublicKey: s.recipient.publicKey,
      itemType: s.itemType,
      ipnsName: s.ipnsName,
      itemName: s.itemName,
      revokedAt: s.revokedAt!,
    }));
  }

  @Get(':shareId/keys')
  @ApiOperation({
    summary: 'Get share keys',
    description: 'Get all re-wrapped child keys for a share. Accessible by sharer or recipient.',
  })
  @ApiResponse({ status: 200, description: 'List of share keys', type: [ShareKeyResponseDto] })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Not authorized to access this share' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  async getShareKeys(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string
  ): Promise<
    Array<{
      keyType: string;
      itemId: string;
      encryptedKey: string;
    }>
  > {
    const keys = await this.sharesService.getShareKeys(shareId, req.user.id);
    return keys.map((k) => ({
      keyType: k.keyType,
      itemId: k.itemId,
      encryptedKey: k.encryptedKey.toString('hex'),
    }));
  }

  @Post(':shareId/keys')
  @ApiOperation({
    summary: 'Add share keys',
    description:
      'Add re-wrapped child keys to an existing share. Allowed for the sharer or write-share recipients.',
  })
  @ApiResponse({ status: 201, description: 'Keys added' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Not authorized to add keys to this share' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  async addShareKeys(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string,
    @Body() dto: AddShareKeysDto
  ): Promise<void> {
    await this.sharesService.addShareKeys(shareId, req.user.id, dto);
  }

  @Patch(':shareId/permission')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Update share permission',
    description:
      'Upgrade or downgrade permission level. Only the sharer can change permission. ' +
      'Upgrading to write requires an ECIES-wrapped IPNS private key.',
  })
  @ApiResponse({ status: 204, description: 'Permission updated' })
  @ApiResponse({ status: 400, description: 'encryptedIpnsKey required for write permission' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Only the sharer can change permission' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  @ApiResponse({ status: 409, description: 'Cannot change permission on a revoked share' })
  async updatePermission(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string,
    @Body() dto: UpdatePermissionDto
  ): Promise<void> {
    await this.sharesService.updatePermission(
      shareId,
      req.user.id,
      dto.permission,
      dto.encryptedIpnsKey
    );
  }

  @Delete(':shareId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Revoke a share',
    description:
      'Soft-delete a share by setting revokedAt. ' +
      'Only the sharer can revoke. Keys are kept for lazy rotation.',
  })
  @ApiResponse({ status: 204, description: 'Share revoked' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Only the sharer can revoke' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  async revokeShare(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string
  ): Promise<void> {
    await this.sharesService.revokeShare(shareId, req.user.id);
  }

  @Patch(':shareId/hide')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Hide a share',
    description: 'Mark a share as hidden by the recipient. Only the recipient can hide.',
  })
  @ApiResponse({ status: 204, description: 'Share hidden' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Only the recipient can hide' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  async hideShare(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string
  ): Promise<void> {
    await this.sharesService.hideShare(shareId, req.user.id);
  }

  @Patch(':shareId/encrypted-key')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Update share encrypted key',
    description:
      'Update the encrypted key on an existing share after lazy key rotation. ' +
      'Only the sharer can update the key.',
  })
  @ApiResponse({ status: 204, description: 'Encrypted key updated' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Only the sharer can update' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  async updateShareEncryptedKey(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string,
    @Body() dto: UpdateEncryptedKeyDto
  ): Promise<void> {
    await this.sharesService.updateShareEncryptedKey(shareId, req.user.id, dto.encryptedKey);
  }

  @Patch(':shareId/item-name')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Backfill share encrypted item name',
    description:
      'Persist the at-rest itemNameEncrypted ciphertext on a legacy share that ' +
      'predates at-rest encryption. Only the sharer can update it; the server ' +
      'never encrypts and stores the client-supplied ciphertext as-is.',
  })
  @ApiResponse({ status: 204, description: 'Item name updated' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Only the sharer can update' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  async updateShareItemName(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string,
    @Body() dto: UpdateItemNameDto
  ): Promise<void> {
    await this.sharesService.updateShareItemName(shareId, req.user.id, dto.itemNameEncrypted);
  }

  @Delete(':shareId/complete-rotation')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Complete key rotation',
    description:
      'Hard-delete a revoked share after the sharer has rotated the folder key. ' +
      'Called after the client performs lazy key rotation.',
  })
  @ApiResponse({ status: 204, description: 'Share hard-deleted after rotation' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Only the sharer can complete rotation' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  @ApiResponse({ status: 409, description: 'Share has not been revoked' })
  async completeRotation(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string
  ): Promise<void> {
    await this.sharesService.completeRotation(shareId, req.user.id);
  }
}

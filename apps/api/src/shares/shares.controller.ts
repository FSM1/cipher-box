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
  NotFoundException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { SharesService } from './shares.service';
import { CreateShareDto } from './dto/create-share.dto';
import { AddShareKeysDto } from './dto/share-key.dto';
import { UpdateEncryptedKeyDto } from './dto/update-encrypted-key.dto';
import {
  CreateShareResponseDto,
  ReceivedShareResponseDto,
  SentShareResponseDto,
  PendingRotationResponseDto,
  ShareKeyResponseDto,
} from './dto/share-response.dto';

interface RequestWithUser extends Request {
  user: {
    id: string;
  };
}

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
    recipientId: string;
    itemType: string;
    ipnsName: string;
    itemName: string;
    encryptedKey: string;
    createdAt: Date;
  }> {
    const share = await this.sharesService.createShare(req.user.id, dto);
    return {
      shareId: share.id,
      recipientId: share.recipientId,
      itemType: share.itemType,
      ipnsName: share.ipnsName,
      itemName: share.itemName,
      encryptedKey: share.encryptedKey.toString('hex'),
      createdAt: share.createdAt,
    };
  }

  @Get('received')
  @ApiOperation({
    summary: 'List received shares',
    description: 'Get all active, non-hidden shares received by the authenticated user.',
  })
  @ApiResponse({
    status: 200,
    description: 'List of received shares',
    type: [ReceivedShareResponseDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getReceivedShares(@Request() req: RequestWithUser): Promise<
    Array<{
      shareId: string;
      sharerPublicKey: string;
      itemType: string;
      ipnsName: string;
      itemName: string;
      encryptedKey: string;
      createdAt: Date;
    }>
  > {
    const shares = await this.sharesService.getReceivedShares(req.user.id);
    return shares.map((s) => ({
      shareId: s.id,
      sharerPublicKey: s.sharer.publicKey,
      itemType: s.itemType,
      ipnsName: s.ipnsName,
      itemName: s.itemName,
      encryptedKey: s.encryptedKey.toString('hex'),
      createdAt: s.createdAt,
    }));
  }

  @Get('sent')
  @ApiOperation({
    summary: 'List sent shares',
    description: 'Get all active shares created by the authenticated user.',
  })
  @ApiResponse({ status: 200, description: 'List of sent shares', type: [SentShareResponseDto] })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getSentShares(@Request() req: RequestWithUser): Promise<
    Array<{
      shareId: string;
      recipientPublicKey: string;
      itemType: string;
      ipnsName: string;
      itemName: string;
      createdAt: Date;
    }>
  > {
    const shares = await this.sharesService.getSentShares(req.user.id);
    return shares.map((s) => ({
      shareId: s.id,
      recipientPublicKey: s.recipient.publicKey,
      itemType: s.itemType,
      ipnsName: s.ipnsName,
      itemName: s.itemName,
      createdAt: s.createdAt,
    }));
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
  @ApiResponse({ status: 200, description: 'User found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async lookupUser(@Query('publicKey') publicKey: string): Promise<{ exists: boolean }> {
    const exists = await this.sharesService.lookupUserByPublicKey(publicKey);
    if (!exists) {
      throw new NotFoundException('User not found');
    }
    return { exists: true };
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
    description: 'Add re-wrapped child keys to an existing share. Only the sharer can add keys.',
  })
  @ApiResponse({ status: 201, description: 'Keys added' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Only the sharer can add keys' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  async addShareKeys(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string,
    @Body() dto: AddShareKeysDto
  ): Promise<void> {
    await this.sharesService.addShareKeys(shareId, req.user.id, dto);
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
  @ApiResponse({ status: 404, description: 'Share not found' })
  async completeRotation(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string
  ): Promise<void> {
    await this.sharesService.completeRotation(shareId, req.user.id);
  }
}

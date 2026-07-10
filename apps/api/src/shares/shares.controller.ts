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
import { UpdateGrantDto } from './dto/update-grant.dto';
import { RevokeForItemsDto } from './dto/revoke-for-items.dto';
import {
  PaginationQueryDto,
  PaginatedReceivedSharesDto,
  PaginatedSentSharesDto,
} from './dto/pagination.dto';
import { CreateShareResponseDto, RevokeForItemsResponseDto } from './dto/share-response.dto';
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
      'The encryptedReadKey is the root readKey + metadata wrapped for the recipient via ECIES.',
  })
  @ApiResponse({ status: 201, description: 'Share created', type: CreateShareResponseDto })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Caller is not the registered owner of the shared node',
  })
  @ApiResponse({ status: 404, description: 'Recipient not found' })
  @ApiResponse({ status: 409, description: 'Share already exists or self-share' })
  async createShare(
    @Request() req: RequestWithUser,
    @Body() dto: CreateShareDto
  ): Promise<CreateShareResponseDto> {
    const share = await this.sharesService.createShare(req.user.id, dto);
    return {
      shareId: share.id,
      recipientPublicKey: dto.recipientPublicKey.startsWith('0x')
        ? dto.recipientPublicKey
        : `0x${dto.recipientPublicKey}`,
      encryptedReadKey: share.encryptedReadKey.toString('hex'),
      encryptedWriteKey: share.encryptedWriteKey ? share.encryptedWriteKey.toString('hex') : null,
      rootNodeId: share.rootNodeId,
      shareRootIpnsName: share.shareRootIpnsName,
      rootGeneration: share.rootGeneration,
      itemNameEncrypted: share.itemNameEncrypted ? share.itemNameEncrypted.toString('hex') : null,
      createdAt: share.createdAt,
    };
  }

  @Post('revoke-for-items')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Bulk hard-delete share grants for deleted items',
    description:
      'Hard-delete every share/invite the authenticated user created for any of ' +
      'the given IPNS names, atomically. Called when an owner deletes a file or ' +
      'folder subtree to the recycle bin so the access cutoff precedes the unpin. ' +
      'Shares are hard-deleted; active invites are marked revoked. ' +
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
    description: 'Get non-hidden shares received by the authenticated user (paginated).',
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
        encryptedReadKey: s.encryptedReadKey.toString('hex'),
        encryptedWriteKey: s.encryptedWriteKey ? s.encryptedWriteKey.toString('hex') : null,
        rootNodeId: s.rootNodeId,
        shareRootIpnsName: s.shareRootIpnsName,
        rootGeneration: s.rootGeneration,
        itemNameEncrypted: s.itemNameEncrypted ? s.itemNameEncrypted.toString('hex') : null,
        createdAt: s.createdAt,
      })),
      total,
    };
  }

  @Get('sent')
  @ApiOperation({
    summary: 'List sent shares',
    description: 'Get shares created by the authenticated user (paginated).',
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
        encryptedReadKey: s.encryptedReadKey.toString('hex'),
        encryptedWriteKey: s.encryptedWriteKey ? s.encryptedWriteKey.toString('hex') : null,
        rootNodeId: s.rootNodeId,
        shareRootIpnsName: s.shareRootIpnsName,
        rootGeneration: s.rootGeneration,
        itemNameEncrypted: s.itemNameEncrypted ? s.itemNameEncrypted.toString('hex') : null,
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

  @Delete(':shareId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Revoke a share',
    description:
      'Hard-delete the grant row (D-11 forward-only revocation). ' + 'Only the sharer can revoke.',
  })
  @ApiResponse({ status: 204, description: 'Share hard-deleted' })
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

  @Patch(':shareId/grant')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Update a share grant key',
    description:
      'Persist a rotated encryptedReadKey and rootGeneration on an existing share. ' +
      'Only the sharer can update it; the server never re-encrypts and stores ' +
      'the client-supplied ciphertext as-is.',
  })
  @ApiResponse({ status: 204, description: 'Grant updated' })
  @ApiResponse({ status: 400, description: 'Invalid request body' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Only the sharer can update' })
  @ApiResponse({ status: 404, description: 'Share not found' })
  async updateGrant(
    @Request() req: RequestWithUser,
    @Param('shareId', ParseUUIDPipe) shareId: string,
    @Body() dto: UpdateGrantDto
  ): Promise<void> {
    await this.sharesService.updateGrant(
      shareId,
      req.user.id,
      dto.encryptedReadKey,
      dto.rootGeneration,
      dto.encryptedWriteKey,
      dto.clearEncryptedWriteKey
    );
  }
}

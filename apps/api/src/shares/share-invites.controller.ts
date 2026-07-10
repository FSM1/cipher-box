import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  ParseUUIDPipe,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { BypassableThrottlerGuard as ThrottlerGuard } from '../common/guards/throttler-bypass.guard';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ShareInviteService } from './share-invite.service';
import { CreateInviteDto } from './dto/create-invite.dto';
import { GetInvitesForItemQueryDto } from './dto/get-invites-for-item-query.dto';
import { InviteResponseDto } from './dto/invite-response.dto';
import { RequestWithUser } from '../common/types';

/**
 * Authenticated invite management controller at /shares/invites prefix.
 * All endpoints require authentication (class-level JwtAuthGuard).
 */
@ApiTags('share-invites')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, ThrottlerGuard)
@Controller('shares/invites')
export class ShareInvitesController {
  constructor(private readonly shareInviteService: ShareInviteService) {}

  /**
   * Create a new invite link for sharing a file or folder.
   * Returns the invite token for URL construction on the client.
   */
  @Post()
  @ApiOperation({
    summary: 'Create an invite link',
    description:
      'Create a new invite link with the root readKey wrapped by an ephemeral public key. ' +
      'Returns the invite token for URL construction. Default expiry: 7 days.',
  })
  @ApiResponse({
    status: 201,
    description: 'Invite created',
    type: InviteResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 403,
    description: 'Caller is not the registered owner of the shared node',
  })
  async createInvite(
    @Request() req: RequestWithUser,
    @Body() dto: CreateInviteDto
  ): Promise<InviteResponseDto> {
    const invite = await this.shareInviteService.createInvite(req.user.id, dto);
    return {
      id: invite.id,
      token: invite.token,
      shareRootIpnsName: invite.shareRootIpnsName,
      rootNodeId: invite.rootNodeId,
      rootGeneration: invite.rootGeneration,
      itemNameEncrypted: invite.itemNameEncrypted ? invite.itemNameEncrypted.toString('hex') : null,
      status: invite.status,
      expiresAt: invite.expiresAt,
      createdAt: invite.createdAt,
    };
  }

  /**
   * List active (unclaimed, unexpired) invites for a specific item.
   * Requires shareRootIpnsName query parameter.
   */
  @Get()
  @ApiOperation({
    summary: 'List active invites for an item',
    description:
      'Get all active (unclaimed, unexpired) invite links created by the authenticated user ' +
      'for the specified item. Expired invites are auto-cleaned.',
  })
  @ApiQuery({
    name: 'shareRootIpnsName',
    description: 'IPNS name of the root shared node',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'List of active invites',
    type: [InviteResponseDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async listInvites(
    @Request() req: RequestWithUser,
    @Query() query: GetInvitesForItemQueryDto
  ): Promise<InviteResponseDto[]> {
    const invites = await this.shareInviteService.getInvitesForItem(
      req.user.id,
      query.shareRootIpnsName
    );
    return invites.map((inv) => ({
      id: inv.id,
      token: inv.token,
      shareRootIpnsName: inv.shareRootIpnsName,
      rootNodeId: inv.rootNodeId,
      rootGeneration: inv.rootGeneration,
      itemNameEncrypted: inv.itemNameEncrypted ? inv.itemNameEncrypted.toString('hex') : null,
      status: inv.status,
      expiresAt: inv.expiresAt,
      createdAt: inv.createdAt,
    }));
  }

  /**
   * Revoke an active invite link.
   * Only the sharer can revoke. Already-claimed shares are unaffected.
   */
  @Delete(':inviteId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Revoke an invite link',
    description:
      'Revoke an active invite link. Only the original sharer can revoke. ' +
      'Already-claimed shares persist independently.',
  })
  @ApiResponse({ status: 204, description: 'Invite revoked' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Only the sharer can revoke' })
  @ApiResponse({ status: 404, description: 'Invite not found' })
  async revokeInvite(
    @Request() req: RequestWithUser,
    @Param('inviteId', ParseUUIDPipe) inviteId: string
  ): Promise<void> {
    await this.shareInviteService.revokeInvite(inviteId, req.user.id);
  }
}

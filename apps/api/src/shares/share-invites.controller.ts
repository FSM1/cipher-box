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
import { ThrottlerGuard } from '@nestjs/throttler';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { SharesService } from './shares.service';
import { CreateInviteDto } from './dto/create-invite.dto';
import { InviteResponseDto } from './dto/invite-response.dto';

interface RequestWithUser extends Request {
  user: {
    id: string;
  };
}

/**
 * Authenticated invite management controller at /shares/invites prefix.
 * All endpoints require authentication (class-level JwtAuthGuard).
 */
@ApiTags('share-invites')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, ThrottlerGuard)
@Controller('shares/invites')
export class ShareInvitesController {
  constructor(private readonly sharesService: SharesService) {}

  /**
   * Create a new invite link for sharing a file or folder.
   * Returns the invite token for URL construction on the client.
   */
  @Post()
  @ApiOperation({
    summary: 'Create an invite link',
    description:
      'Create a new invite link with the item key wrapped by an ephemeral public key. ' +
      'Returns the invite token for URL construction. Default expiry: 7 days.',
  })
  @ApiResponse({
    status: 201,
    description: 'Invite created',
    type: InviteResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async createInvite(
    @Request() req: RequestWithUser,
    @Body() dto: CreateInviteDto
  ): Promise<{
    token: string;
    itemType: string;
    ipnsName: string;
    itemName: string;
    status: string;
    expiresAt: Date;
    createdAt: Date;
  }> {
    const invite = await this.sharesService.createInvite(req.user.id, dto);
    return {
      token: invite.token,
      itemType: invite.itemType,
      ipnsName: invite.ipnsName,
      itemName: invite.itemName,
      status: invite.status,
      expiresAt: invite.expiresAt,
      createdAt: invite.createdAt,
    };
  }

  /**
   * List active (unclaimed, unexpired) invites for a specific item.
   * Requires ipnsName query parameter.
   */
  @Get()
  @ApiOperation({
    summary: 'List active invites for an item',
    description:
      'Get all active (unclaimed, unexpired) invite links created by the authenticated user ' +
      'for the specified item. Expired invites are auto-cleaned.',
  })
  @ApiQuery({
    name: 'ipnsName',
    description: 'IPNS name of the item to list invites for',
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
    @Query('ipnsName') ipnsName: string
  ): Promise<
    Array<{
      token: string;
      itemType: string;
      ipnsName: string;
      itemName: string;
      status: string;
      expiresAt: Date;
      createdAt: Date;
    }>
  > {
    const invites = await this.sharesService.getInvitesForItem(req.user.id, ipnsName);
    return invites.map((inv) => ({
      token: inv.token,
      itemType: inv.itemType,
      ipnsName: inv.ipnsName,
      itemName: inv.itemName,
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
    await this.sharesService.revokeInvite(inviteId, req.user.id);
  }
}

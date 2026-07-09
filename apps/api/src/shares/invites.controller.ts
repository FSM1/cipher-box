import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  Request,
  NotFoundException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiParam } from '@nestjs/swagger';
import { BypassableThrottlerGuard as ThrottlerGuard } from '../common/guards/throttler-bypass.guard';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ShareInviteService } from './share-invite.service';
import { ClaimInviteDto } from './dto/claim-invite.dto';
import {
  InviteStatusResponseDto,
  InviteDataResponseDto,
  ClaimInviteResponseDto,
} from './dto/invite-response.dto';
import { RequestWithUser } from '../common/types';
import { ParseTokenPipe } from '../common/pipes/parse-token.pipe';

/**
 * Public-facing invite controller at /invites prefix.
 * NO class-level auth guard -- individual endpoints opt in.
 */
@ApiTags('invites')
@Controller('invites')
export class InvitesController {
  constructor(private readonly shareInviteService: ShareInviteService) {}

  /**
   * PUBLIC: No auth required -- returns only the invite status.
   * Used by the invite landing page before the recipient logs in.
   * Opaque: no file name, no sharer identity.
   */
  @Get(':token')
  @UseGuards(ThrottlerGuard)
  @ApiOperation({
    summary: 'Get invite status (public)',
    description:
      'Check the status of an invite link. Returns only status -- ' +
      'no file name or sharer identity is revealed before authentication.',
  })
  @ApiParam({ name: 'token', description: 'Invite token (URL-safe base64)' })
  @ApiResponse({
    status: 200,
    description: 'Invite status',
    type: InviteStatusResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Invite not found or expired' })
  async getInviteStatus(
    @Param('token', ParseTokenPipe) token: string
  ): Promise<{ status: string }> {
    const result = await this.shareInviteService.getInviteStatus(token);
    if (!result || result.status !== 'active') {
      throw new NotFoundException();
    }
    return { status: 'active' };
  }

  /**
   * AUTHENTICATED: Returns full invite data needed for the claim flow.
   * The client uses the encrypted key ciphertext to unwrap with the
   * ephemeral private key (from URL fragment) and re-wrap with their own key.
   */
  @Get(':token/data')
  @UseGuards(JwtAuthGuard, ThrottlerGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get invite data for claim flow (authenticated)',
    description:
      'Fetch full invite data including encrypted key ciphertext and root identity. ' +
      'Requires authentication. Used by the client claim flow.',
  })
  @ApiParam({ name: 'token', description: 'Invite token (URL-safe base64)' })
  @ApiResponse({
    status: 200,
    description: 'Full invite data for claim flow',
    type: InviteDataResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Invite not found or expired' })
  async getInviteData(
    @Param('token', ParseTokenPipe) token: string
  ): Promise<InviteDataResponseDto> {
    const invite = await this.shareInviteService.getInviteForClaim(token);

    if (!invite) {
      throw new NotFoundException('Invite not found or expired');
    }

    return {
      status: invite.status,
      encryptedReadKey: invite.encryptedReadKey.toString('hex'),
      encryptedWriteKey: invite.encryptedWriteKey ? invite.encryptedWriteKey.toString('hex') : null,
      rootNodeId: invite.rootNodeId,
      shareRootIpnsName: invite.shareRootIpnsName,
      rootGeneration: invite.rootGeneration,
      itemNameEncrypted: invite.itemNameEncrypted ? invite.itemNameEncrypted.toString('hex') : null,
    };
  }

  /**
   * AUTHENTICATED: Claim an invite by providing re-wrapped encrypted keys.
   * Creates a single encrypted-key Share via the sharing infrastructure (D-05).
   */
  @Post(':token/claim')
  @UseGuards(JwtAuthGuard, ThrottlerGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Claim an invite link',
    description:
      'Claim an invite by providing the encrypted key re-wrapped for the recipient. ' +
      'Creates a single Share row. Single-claim enforced atomically.',
  })
  @ApiParam({ name: 'token', description: 'Invite token (URL-safe base64)' })
  @ApiResponse({
    status: 201,
    description: 'Invite claimed successfully',
    type: ClaimInviteResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Invite not found or expired' })
  @ApiResponse({ status: 409, description: 'Invite already claimed or self-claim' })
  async claimInvite(
    @Request() req: RequestWithUser,
    @Param('token', ParseTokenPipe) token: string,
    @Body() dto: ClaimInviteDto
  ): Promise<{ shareId: string }> {
    return this.shareInviteService.claimInvite(token, req.user.id, dto);
  }
}

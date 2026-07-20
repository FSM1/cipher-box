import { Body, Controller, Delete, Get, Param, Post, Req, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AuthenticatedRequest, JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_SURFACES } from '../ops/throttling';
import {
  AckResponseDto,
  MailboxMessageDto,
  PollResponseDto,
  PostMessageDto,
  PostMessageResponseDto,
} from './dto/mailbox.dto';
import { MailboxService } from './services/mailbox.service';

/**
 * The integrity-untrusted mailbox surface (blueprint/api.md, Mailbox): post a
 * sealed pointer to a recipient pubkey, poll your own mailbox, ack-delete by
 * id. Every route is authenticated; blobs are opaque and never inspected.
 */
@ApiTags('Mailbox')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('mailbox')
export class MailboxController {
  constructor(private readonly mailboxService: MailboxService) {}

  @Post('messages')
  @Throttle(THROTTLE_SURFACES.mailboxPost)
  @ApiOperation({
    summary:
      'Post an HPKE-sealed blob to a recipient identity publicKey; unknown recipients are rejected (rate-limited existence oracle)',
  })
  @ApiCreatedResponse({ type: PostMessageResponseDto })
  @ApiResponse({ status: 400, description: 'Malformed body (invalid publicKey, blob, or key)' })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 404, description: 'Unknown recipient (rate-limited existence oracle)' })
  @ApiResponse({
    status: 409,
    description: 'Recipient mailbox is full (per-recipient pending cap)',
  })
  @ApiResponse({ status: 413, description: 'Sealed blob exceeds 8 KiB' })
  @ApiResponse({ status: 429, description: 'Per-sender post rate limit exceeded' })
  post(
    @Body() body: PostMessageDto,
    @Req() request: AuthenticatedRequest
  ): Promise<PostMessageResponseDto> {
    return this.mailboxService.post(request.user.publicKey, body);
  }

  @Get('messages')
  @Throttle(THROTTLE_SURFACES.mailboxPoll)
  @ApiOperation({
    summary:
      'Poll the authenticated mailbox; returns sealed blobs with no sender metadata in the clear',
  })
  @ApiOkResponse({ type: PollResponseDto })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Per-recipient poll rate limit exceeded' })
  async poll(@Req() request: AuthenticatedRequest): Promise<PollResponseDto> {
    const { messages } = await this.mailboxService.poll(request.user.publicKey);
    return { messages: messages as MailboxMessageDto[] };
  }

  @Delete('messages/:id')
  @Throttle(THROTTLE_SURFACES.mailboxAck)
  @ApiOperation({ summary: 'Ack a message: hard delete by id, scoped to the caller mailbox' })
  @ApiOkResponse({ type: AckResponseDto })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Per-recipient ack rate limit exceeded' })
  ack(@Param('id') id: string, @Req() request: AuthenticatedRequest): Promise<AckResponseDto> {
    return this.mailboxService.ack(request.user.publicKey, id);
  }
}

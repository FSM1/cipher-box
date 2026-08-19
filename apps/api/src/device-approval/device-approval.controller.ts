import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AllowScope } from '../auth/decorators/allow-scope.decorator';
import { AuthenticatedRequest, JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_SURFACES } from '../ops/throttling';
import {
  ApprovalActionResponseDto,
  ApprovalStatusDto,
  CreateApprovalDto,
  CreateApprovalResponseDto,
  PendingApprovalDto,
  PendingApprovalListDto,
  RespondApprovalDto,
} from './dto/device-approval.dto';
import { DeviceApprovalService } from './services/device-approval.service';

/**
 * The device-approval rendezvous (ADR 0009 D1). The API is a bulletin board: it
 * relays the requester's ephemeral key and the approver's sealed ciphertext, and
 * neither generates, substitutes, nor inspects either.
 */
@ApiTags('Device Approval')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('device-approval')
export class DeviceApprovalController {
  constructor(private readonly approvals: DeviceApprovalService) {}

  @Post('requests')
  @AllowScope('device-approval')
  @Throttle(THROTTLE_SURFACES.deviceApprovalRequest)
  @ApiOperation({ summary: 'Open a rendezvous, signed over the ephemeral key it offers' })
  @ApiCreatedResponse({ type: CreateApprovalResponseDto })
  @ApiResponse({ status: 400, description: 'Malformed device key, ephemeral key, or signature' })
  @ApiResponse({
    status: 401,
    description: 'Missing token, or the request signature does not verify',
  })
  @ApiResponse({ status: 409, description: 'Too many pending approval requests' })
  @ApiResponse({ status: 429, description: 'Per-account request rate limit exceeded' })
  @ApiResponse({ status: 503, description: 'Account serialization contended; retry shortly' })
  create(
    @Body() body: CreateApprovalDto,
    @Req() request: AuthenticatedRequest
  ): Promise<CreateApprovalResponseDto> {
    return this.approvals.createRequest(request.user.userId, body);
  }

  @Get('requests/:requestId')
  @AllowScope('device-approval')
  @Throttle(THROTTLE_SURFACES.deviceApprovalPoll)
  @ApiOperation({
    summary: 'Poll a rendezvous; a settled one is served once and its row is then gone',
  })
  @ApiOkResponse({ type: ApprovalStatusDto })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 404, description: 'Unknown, expired, or already collected request' })
  @ApiResponse({ status: 429, description: 'Per-account poll rate limit exceeded' })
  status(
    @Param('requestId') requestId: string,
    @Req() request: AuthenticatedRequest
  ): Promise<ApprovalStatusDto> {
    return this.approvals.status(request.user.userId, requestId);
  }

  @Delete('requests/:requestId')
  @AllowScope('device-approval')
  @Throttle(THROTTLE_SURFACES.deviceApprovalPoll)
  @ApiOperation({ summary: 'Abandon a rendezvous: hard delete, scoped to the caller account' })
  @ApiOkResponse({ type: ApprovalActionResponseDto })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Per-account poll rate limit exceeded' })
  async cancel(
    @Param('requestId') requestId: string,
    @Req() request: AuthenticatedRequest
  ): Promise<ApprovalActionResponseDto> {
    await this.approvals.cancel(request.user.userId, requestId);
    return { success: true };
  }

  @Get('pending')
  @Throttle(THROTTLE_SURFACES.deviceApprovalPoll)
  @ApiOperation({
    summary:
      'What this account is being asked to approve; requires a full session, not a scoped token',
  })
  @ApiOkResponse({ type: PendingApprovalListDto })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 403, description: 'A scoped pre-reconstruction token cannot approve' })
  @ApiResponse({ status: 429, description: 'Per-account poll rate limit exceeded' })
  async pending(@Req() request: AuthenticatedRequest): Promise<PendingApprovalListDto> {
    const requests = await this.approvals.pending(request.user.userId);
    return { requests: requests as PendingApprovalDto[] };
  }

  @Post('requests/:requestId/respond')
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.deviceApprovalRespond)
  @ApiOperation({
    summary: 'Approve or deny, signed by a registered device over the stored ephemeral key',
  })
  @ApiOkResponse({ type: ApprovalActionResponseDto })
  @ApiResponse({
    status: 400,
    description: 'Self-approval, or a decision whose sealed factor does not match it',
  })
  @ApiResponse({
    status: 401,
    description: 'Unregistered responding device, or the response signature does not verify',
  })
  @ApiResponse({ status: 403, description: 'A scoped pre-reconstruction token cannot approve' })
  @ApiResponse({ status: 404, description: 'Unknown, expired, or already answered request' })
  @ApiResponse({ status: 413, description: 'Sealed factor exceeds 1 KiB' })
  @ApiResponse({ status: 429, description: 'Per-account respond rate limit exceeded' })
  async respond(
    @Param('requestId') requestId: string,
    @Body() body: RespondApprovalDto,
    @Req() request: AuthenticatedRequest
  ): Promise<ApprovalActionResponseDto> {
    await this.approvals.respond(request.user.userId, requestId, body);
    return { success: true };
  }
}

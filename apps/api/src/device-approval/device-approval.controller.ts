import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  UseGuards,
  Request,
  ParseUUIDPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { DeviceApprovalService } from './device-approval.service';
import { CreateApprovalDto } from './dto/create-approval.dto';
import { RespondApprovalDto } from './dto/respond-approval.dto';

interface RequestWithUser extends Request {
  user: {
    id: string;
  };
}

@ApiTags('device-approval')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('device-approval')
export class DeviceApprovalController {
  constructor(private readonly deviceApprovalService: DeviceApprovalService) {}

  @Post('request')
  @ApiOperation({
    summary: 'Create device approval request',
    description:
      'New device creates an approval request with an ephemeral ' +
      'public key for ECIES key exchange. Request expires after ' +
      '5 minutes.',
  })
  @ApiResponse({
    status: 201,
    description: 'Approval request created',
    schema: {
      properties: {
        requestId: { type: 'string', format: 'uuid' },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async createRequest(
    @Request() req: RequestWithUser,
    @Body() dto: CreateApprovalDto
  ): Promise<{ requestId: string }> {
    return this.deviceApprovalService.createRequest(req.user.id, dto);
  }

  @Get(':requestId/status')
  @ApiOperation({
    summary: 'Poll approval request status',
    description:
      'New device polls this endpoint to check if the request ' +
      'has been approved, denied, or expired. Returns the ' +
      'encrypted factor key on approval.',
  })
  @ApiResponse({
    status: 200,
    description: 'Approval status',
    schema: {
      properties: {
        status: {
          type: 'string',
          enum: ['pending', 'approved', 'denied', 'expired'],
        },
        encryptedFactorKey: {
          type: 'string',
          nullable: true,
          description: 'ECIES-encrypted factor key (hex)',
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 404,
    description: 'Request not found',
  })
  async getStatus(
    @Request() req: RequestWithUser,
    @Param('requestId', ParseUUIDPipe) requestId: string
  ): Promise<{ status: string; encryptedFactorKey?: string }> {
    return this.deviceApprovalService.getStatus(requestId, req.user.id);
  }

  @Get('pending')
  @ApiOperation({
    summary: 'List pending approval requests',
    description:
      'Existing device fetches all non-expired pending approval ' +
      'requests for the authenticated user.',
  })
  @ApiResponse({
    status: 200,
    description: 'List of pending approval requests',
    schema: {
      type: 'array',
      items: {
        properties: {
          requestId: { type: 'string', format: 'uuid' },
          deviceId: { type: 'string' },
          deviceName: { type: 'string' },
          ephemeralPublicKey: { type: 'string' },
          createdAt: { type: 'string', format: 'date-time' },
          expiresAt: { type: 'string', format: 'date-time' },
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getPending(@Request() req: RequestWithUser): Promise<
    Array<{
      requestId: string;
      deviceId: string;
      deviceName: string;
      ephemeralPublicKey: string;
      createdAt: Date;
      expiresAt: Date;
    }>
  > {
    return this.deviceApprovalService.getPending(req.user.id);
  }

  @Post(':requestId/respond')
  @ApiOperation({
    summary: 'Respond to approval request',
    description:
      'Existing device approves or denies an approval request. ' +
      'On approve, includes the ECIES-encrypted factor key.',
  })
  @ApiResponse({
    status: 200,
    description: 'Response recorded',
  })
  @ApiResponse({ status: 400, description: 'Already responded or expired' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Request not found' })
  async respond(
    @Request() req: RequestWithUser,
    @Param('requestId', ParseUUIDPipe) requestId: string,
    @Body() dto: RespondApprovalDto
  ): Promise<void> {
    return this.deviceApprovalService.respond(requestId, req.user.id, dto);
  }

  @Delete(':requestId')
  @ApiOperation({
    summary: 'Cancel approval request',
    description:
      'New device cancels its own pending approval request ' +
      '(cleanup on navigation away or recovery phrase used).',
  })
  @ApiResponse({ status: 200, description: 'Request cancelled' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({
    status: 404,
    description: 'Request not found or not pending',
  })
  async cancel(
    @Request() req: RequestWithUser,
    @Param('requestId', ParseUUIDPipe) requestId: string
  ): Promise<void> {
    return this.deviceApprovalService.cancel(requestId, req.user.id);
  }
}

import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { THROTTLE_SURFACES } from '../ops/throttling';
import {
  DeviceApprovalSessionDto,
  DeviceApprovalSessionResponseDto,
} from './dto/device-approval.dto';
import { DeviceApprovalService } from './services/device-approval.service';

/**
 * The pre-reconstruction session mint (ADR 0009 D1), alone on its own controller
 * because it is the one route in this slice with no bearer to check — the caller
 * is a device that cannot yet derive its key. Its siblings sit behind a
 * class-level guard, which a route added there then inherits.
 */
@ApiTags('Device Approval')
@Controller('device-approval')
export class DeviceApprovalSessionController {
  constructor(private readonly approvals: DeviceApprovalService) {}

  @Post('session')
  @HttpCode(200)
  @Throttle(THROTTLE_SURFACES.deviceApprovalSession)
  @ApiOperation({
    summary:
      'Exchange a CipherBox identity token for a scoped, non-refreshable pre-reconstruction token',
  })
  @ApiOkResponse({ type: DeviceApprovalSessionResponseDto })
  @ApiResponse({ status: 400, description: 'Malformed or oversized identity token' })
  @ApiResponse({ status: 401, description: 'Invalid identity token' })
  @ApiResponse({ status: 404, description: 'No registered device can approve this identity' })
  @ApiResponse({ status: 429, description: 'Per-IP session rate limit exceeded' })
  session(@Body() body: DeviceApprovalSessionDto): Promise<DeviceApprovalSessionResponseDto> {
    return this.approvals.openSession(body.identityToken);
  }
}

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
  ApprovalActionResponseDto,
  RegisterDeviceDto,
  RegisteredDeviceDto,
  RegisteredDeviceListDto,
} from './dto/device-approval.dto';
import { AccountDeviceService } from './services/account-device.service';

/** The account's device registry (ADR 0009 D4). */
@ApiTags('Devices')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('devices')
export class DeviceController {
  constructor(private readonly devices: AccountDeviceService) {}

  @Post()
  @Throttle(THROTTLE_SURFACES.deviceRegistry)
  @ApiOperation({
    summary: 'Register this device identity key, proving possession by signing the account id',
  })
  @ApiCreatedResponse({ type: RegisteredDeviceDto })
  @ApiResponse({ status: 400, description: 'Malformed publicKey, signature, or label' })
  @ApiResponse({
    status: 401,
    description: 'Missing token, an invalid identity token, or a signature that does not verify',
  })
  @ApiResponse({
    status: 409,
    description: 'Key or identity already claimed elsewhere, or the device limit is reached',
  })
  @ApiResponse({ status: 429, description: 'Per-account registry rate limit exceeded' })
  @ApiResponse({ status: 503, description: 'Account serialization contended; retry shortly' })
  register(
    @Body() body: RegisterDeviceDto,
    @Req() request: AuthenticatedRequest
  ): Promise<RegisteredDeviceDto> {
    return this.devices.register(request.user.userId, body);
  }

  @Get()
  @Throttle(THROTTLE_SURFACES.deviceRegistry)
  @ApiOperation({ summary: 'The device identity keys registered to the authenticated account' })
  @ApiOkResponse({ type: RegisteredDeviceListDto })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Per-account registry rate limit exceeded' })
  async list(@Req() request: AuthenticatedRequest): Promise<RegisteredDeviceListDto> {
    return { devices: await this.devices.list(request.user.userId) };
  }

  @Delete(':id')
  @Throttle(THROTTLE_SURFACES.deviceRegistry)
  @ApiOperation({
    summary:
      'Revoke a device key: a hard delete. It stops that device approving from now on; it does ' +
      'not un-share what the device already holds (ADR 0009 D5).',
  })
  @ApiOkResponse({ type: ApprovalActionResponseDto })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 429, description: 'Per-account registry rate limit exceeded' })
  async revoke(
    @Param('id') id: string,
    @Req() request: AuthenticatedRequest
  ): Promise<ApprovalActionResponseDto> {
    await this.devices.revoke(request.user.userId, id);
    return { success: true };
  }
}

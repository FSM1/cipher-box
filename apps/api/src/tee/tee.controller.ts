import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { TeeService } from './tee.service';
import { ConnectionTestRequestDto, ConnectionTestResponseDto } from './dto/connection-test.dto';

@ApiTags('tee')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('tee')
export class TeeController {
  constructor(private readonly teeService: TeeService) {}

  @Post('connection-test')
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiOperation({
    summary: 'Test connection to an external IPFS provider via TEE',
    description:
      'Forwards ECIES-encrypted provider config to TEE worker for server-side connection testing. ' +
      'Avoids browser CORS issues and keeps credentials encrypted until decrypted in-enclave.',
  })
  @ApiResponse({ status: 200, type: ConnectionTestResponseDto })
  async connectionTest(@Body() dto: ConnectionTestRequestDto): Promise<ConnectionTestResponseDto> {
    return this.teeService.connectionTest(dto.encryptedConfig, dto.epoch);
  }
}

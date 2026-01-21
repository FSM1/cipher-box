import { Controller, Post, Body, UseGuards, Request } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { IpnsService } from './ipns.service';
import { PublishIpnsDto, PublishIpnsResponseDto } from './dto';

interface RequestWithUser extends Request {
  user: {
    id: string;
  };
}

@ApiTags('IPNS')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, ThrottlerGuard)
@Controller('ipns')
export class IpnsController {
  constructor(private readonly ipnsService: IpnsService) {}

  // [SECURITY: HIGH-04] Rate limit IPNS publish to prevent abuse
  // Each publish makes external HTTP calls to delegated-ipfs.dev
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 publishes per minute per user
  @Post('publish')
  @ApiOperation({
    summary: 'Publish IPNS record',
    description:
      'Relay a pre-signed IPNS record to the IPFS network via delegated routing. ' +
      'The client signs the record locally; backend relays to delegated-ipfs.dev and tracks ' +
      'the folder for TEE republishing.',
  })
  @ApiResponse({
    status: 200,
    description: 'IPNS record published successfully',
    type: PublishIpnsResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid record format or missing required fields',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  @ApiResponse({
    status: 502,
    description: 'Bad Gateway - Failed to publish to delegated routing',
  })
  async publishRecord(
    @Request() req: RequestWithUser,
    @Body() dto: PublishIpnsDto
  ): Promise<PublishIpnsResponseDto> {
    return this.ipnsService.publishRecord(req.user.id, dto);
  }
}

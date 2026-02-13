import {
  Controller,
  Post,
  Get,
  Body,
  Query,
  UseGuards,
  Request,
  NotFoundException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { IpnsService } from './ipns.service';
import {
  PublishIpnsDto,
  PublishIpnsResponseDto,
  ResolveIpnsQueryDto,
  ResolveIpnsResponseDto,
} from './dto';

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

  // [SECURITY: HIGH-04] Rate limit IPNS resolve - higher limit than publish since read-only
  @Throttle({ default: { limit: 30, ttl: 60000 } }) // 30 resolves per minute per user
  @Get('resolve')
  @ApiOperation({
    summary: 'Resolve IPNS name',
    description:
      'Resolve an IPNS name to its current CID via delegated routing. ' +
      'Returns the CID and sequence number of the current IPNS record.',
  })
  @ApiQuery({
    name: 'ipnsName',
    description:
      'IPNS name to resolve. Supports CIDv1 IPNS names starting with "k51..." (PeerID-style) or "bafzaa..." (IPNS key CID).',
    example: 'k51qzi5uqu5dkkciu33khkzbcmxtyhn2hgdqyp6rv7s5egjlsdj6a2xpz9lxvz',
  })
  @ApiResponse({
    status: 200,
    description: 'IPNS name resolved successfully',
    type: ResolveIpnsResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request - Invalid IPNS name format',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  @ApiResponse({
    status: 404,
    description: 'Not Found - IPNS name not published or not found in routing network',
  })
  @ApiResponse({
    status: 502,
    description: 'Bad Gateway - Failed to resolve from delegated routing',
  })
  async resolveRecord(@Query() query: ResolveIpnsQueryDto): Promise<ResolveIpnsResponseDto> {
    const result = await this.ipnsService.resolveRecord(query.ipnsName);

    if (!result) {
      throw new NotFoundException('IPNS name not found in routing network');
    }

    // Include signature fields as all-or-nothing bundle for client verification
    const hasSigData = result.signatureV2 && result.data && result.pubKey;
    return {
      success: true,
      cid: result.cid,
      sequenceNumber: result.sequenceNumber,
      ...(hasSigData && {
        signatureV2: result.signatureV2,
        data: result.data,
        pubKey: result.pubKey,
      }),
    };
  }
}

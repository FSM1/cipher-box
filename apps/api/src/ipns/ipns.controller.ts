import { Controller, Post, Body, UseGuards, Request } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
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
@UseGuards(JwtAuthGuard)
@Controller('ipns')
export class IpnsController {
  constructor(private readonly ipnsService: IpnsService) {}

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

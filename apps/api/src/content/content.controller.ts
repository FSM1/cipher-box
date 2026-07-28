import { BadRequestException, Controller, Post, Req, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiCreatedResponse,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { AuthenticatedRequest, JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { ContentService } from './content.service';
import { UploadResponseDto, UploadTooLargeDto } from './dto/content.dto';
import { QUOTA_EXCEEDED, UPLOAD_TOO_LARGE } from './upload-error-codes';

/**
 * The hosted content ingress surface (blueprint/api.md, Content plane): an
 * authenticated, quota-gated upload that pins opaque bytes to CipherBox Kubo.
 * The raw `application/octet-stream` body is buffered by the global raw-body
 * middleware (app-setup); BYO/dual byte paths bypass the API entirely.
 */
@ApiTags('Content')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('content')
export class ContentController {
  constructor(private readonly contentService: ContentService) {}

  @Post('upload')
  @Throttle(THROTTLE_SURFACES.content)
  @ApiOperation({
    summary:
      'Upload content bytes to the hosted pin store; quota-gated for hosted accounts, refused for BYO',
  })
  @ApiConsumes('application/octet-stream')
  @ApiBody({ schema: { type: 'string', format: 'binary' } })
  @ApiCreatedResponse({ type: UploadResponseDto })
  @ApiResponse({ status: 400, description: 'Empty or non-binary upload body' })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({
    status: 409,
    description: 'Hosted ingress is unavailable for BYO accounts; pin to your own provider',
  })
  @ApiResponse({
    status: 413,
    type: UploadTooLargeDto,
    description:
      'Two unrelated causes share this status; discriminate on the body `code`, never on `message`. ' +
      `\`${UPLOAD_TOO_LARGE}\`: the body exceeded the transport cap MAX_UPLOAD_BYTES — permanent, so retrying the same body always fails. ` +
      `\`${QUOTA_EXCEEDED}\`: the account storage quota gate refused it — transient, so the same body succeeds once space is freed.`,
  })
  @ApiResponse({ status: 429, description: 'Upload rate limit exceeded' })
  @ApiResponse({ status: 503, description: 'Pin store contended or unavailable; retry shortly' })
  upload(@Req() request: AuthenticatedRequest): Promise<UploadResponseDto> {
    const body: unknown = request.body;
    if (!Buffer.isBuffer(body) || body.length === 0) {
      throw new BadRequestException('Empty or non-binary upload body');
    }
    return this.contentService.upload(request.user.userId, body);
  }
}

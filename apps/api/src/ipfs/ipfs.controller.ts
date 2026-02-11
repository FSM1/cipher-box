import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  ParseFilePipe,
  MaxFileSizeValidator,
  Inject,
  Res,
  StreamableFile,
  Request,
  PayloadTooLargeException,
} from '@nestjs/common';
import { Response, Request as ExpressRequest } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiConsumes,
  ApiBody,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { IPFS_PROVIDER, IpfsProvider } from './providers';
import { UploadResponseDto, UnpinDto, UnpinResponseDto } from './dto';
import { VaultService } from '../vault/vault.service';

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

interface RequestWithUser extends ExpressRequest {
  user: { id: string };
}

@ApiTags('IPFS')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('ipfs')
export class IpfsController {
  constructor(
    @Inject(IPFS_PROVIDER) private readonly ipfsProvider: IpfsProvider,
    private readonly vaultService: VaultService
  ) {}

  @Post('upload')
  @ApiOperation({
    summary: 'Upload encrypted file to IPFS with quota tracking',
    description:
      'Pins encrypted file to IPFS, checks storage quota, and records the pin for quota tracking. All in one atomic request.',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          format: 'binary',
          description: 'Encrypted file blob (max 100MB)',
        },
      },
      required: ['file'],
    },
  })
  @ApiResponse({
    status: 201,
    description: 'File uploaded, pinned, and recorded successfully',
    type: UploadResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  @ApiResponse({
    status: 413,
    description: 'Storage quota exceeded',
  })
  @UseInterceptors(
    FileInterceptor('file', {
      limits: { fileSize: MAX_FILE_SIZE },
    })
  )
  async upload(
    @Request() req: RequestWithUser,
    @UploadedFile(
      new ParseFilePipe({
        validators: [new MaxFileSizeValidator({ maxSize: MAX_FILE_SIZE })],
      })
    )
    file: Express.Multer.File
  ): Promise<UploadResponseDto> {
    const hasQuota = await this.vaultService.checkQuota(req.user.id, file.size);
    if (!hasQuota) throw new PayloadTooLargeException('Storage quota exceeded');
    const result = await this.ipfsProvider.pinFile(file.buffer);
    try {
      await this.vaultService.recordPin(req.user.id, result.cid, result.size);
    } catch (err) {
      await this.ipfsProvider.unpinFile(result.cid).catch(() => undefined);
      throw err;
    }
    return { cid: result.cid, size: result.size, recorded: true };
  }

  @Post('unpin')
  @ApiOperation({
    summary: 'Unpin file from IPFS',
    description: 'Remove a pinned file from IPFS via Pinata using its CID.',
  })
  @ApiResponse({
    status: 201,
    description: 'File unpinned successfully',
    type: UnpinResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  async unpin(@Body() dto: UnpinDto): Promise<UnpinResponseDto> {
    await this.ipfsProvider.unpinFile(dto.cid);
    return { success: true };
  }

  @Get(':cid')
  @ApiOperation({
    summary: 'Get file from IPFS',
    description: 'Download an encrypted file from IPFS via the configured gateway.',
  })
  @ApiResponse({
    status: 200,
    description: 'File retrieved successfully',
    content: {
      'application/octet-stream': {
        schema: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  @ApiResponse({
    status: 404,
    description: 'File not found',
  })
  async get(
    @Param('cid') cid: string,
    @Res({ passthrough: true }) res: Response
  ): Promise<StreamableFile> {
    const buffer = await this.ipfsProvider.getFile(cid);
    res.set({
      'Content-Type': 'application/octet-stream',
      'Content-Length': buffer.length.toString(),
    });
    return new StreamableFile(buffer);
  }
}

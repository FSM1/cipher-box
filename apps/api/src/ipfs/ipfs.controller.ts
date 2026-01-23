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
} from '@nestjs/common';
import { Response } from 'express';
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
import { AddResponseDto, UnpinDto, UnpinResponseDto } from './dto';

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

@ApiTags('IPFS')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('ipfs')
export class IpfsController {
  constructor(@Inject(IPFS_PROVIDER) private readonly ipfsProvider: IpfsProvider) {}

  @Post('add')
  @ApiOperation({
    summary: 'Pin encrypted file to IPFS',
    description: 'Upload an encrypted file blob to IPFS via Pinata. Returns the CID and size.',
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
    description: 'File pinned successfully',
    type: AddResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT token required',
  })
  @ApiResponse({
    status: 413,
    description: 'Payload too large - file exceeds 100MB limit',
  })
  @UseInterceptors(
    FileInterceptor('file', {
      limits: { fileSize: MAX_FILE_SIZE },
    })
  )
  async add(
    @UploadedFile(
      new ParseFilePipe({
        validators: [new MaxFileSizeValidator({ maxSize: MAX_FILE_SIZE })],
      })
    )
    file: Express.Multer.File
  ): Promise<AddResponseDto> {
    const result = await this.ipfsProvider.pinFile(file.buffer);
    return result;
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

import {
  Controller,
  Post,
  Body,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  ParseFilePipe,
  MaxFileSizeValidator,
} from '@nestjs/common';
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
import { IpfsService } from './ipfs.service';
import { AddResponseDto, UnpinDto, UnpinResponseDto } from './dto';

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

@ApiTags('IPFS')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('ipfs')
export class IpfsController {
  constructor(private readonly ipfsService: IpfsService) {}

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
    const result = await this.ipfsService.pinFile(file.buffer);
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
    await this.ipfsService.unpinFile(dto.cid);
    return { success: true };
  }
}

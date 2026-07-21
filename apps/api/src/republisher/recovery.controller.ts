import {
  Controller,
  Get,
  NotFoundException,
  Param,
  StreamableFile,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { RecordCacheService } from './services/record-cache.service';

const IPNS_RECORD_MEDIA_TYPE = 'application/vnd.ipfs.ipns-record';
/** A bare CID/name token; matches the registry's zero-knowledge name shape. */
const IPNS_NAME = /^[A-Za-z0-9]{1,128}$/;

/**
 * The recovery endpoint (blueprint/api.md, Republisher module and recovery):
 * authenticated, rate-limited fetch of cached (possibly EOL-expired) record
 * bytes by name — the revival aid after a >EOL liveness lapse, where a
 * key-holder extracts the last CID and mints a fresh record.
 *
 * This is the ONLY path by which the API serves a record, and it is explicitly
 * NOT a resolve path: the cache is non-canonical, so a caller still verifies the
 * bytes against the network itself. The API never inspects the record.
 */
@ApiTags('Recovery')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('recovery')
export class RecoveryController {
  constructor(private readonly cache: RecordCacheService) {}

  @Get(':ipnsName')
  @Throttle(THROTTLE_SURFACES.recovery)
  @ApiOperation({
    summary:
      'Fetch cached (possibly expired) record bytes for a name — the revival aid after a >EOL lapse. Non-canonical: verify against the network.',
  })
  @ApiParam({ name: 'ipnsName', description: 'The IPNS name (libp2p-key CID)' })
  @ApiResponse({
    status: 200,
    description: 'Opaque signed record bytes',
    content: { [IPNS_RECORD_MEDIA_TYPE]: { schema: { type: 'string', format: 'binary' } } },
  })
  @ApiResponse({ status: 401, description: 'Missing or invalid access token' })
  @ApiResponse({ status: 404, description: 'No cached record for this name' })
  @ApiResponse({ status: 429, description: 'Recovery rate limit exceeded' })
  async fetch(@Param('ipnsName') ipnsName: string): Promise<StreamableFile> {
    // A malformed name can never key a server-minted row; treat it as absent so
    // the `varchar`-typed lookup never faults and the endpoint reveals nothing.
    if (!IPNS_NAME.test(ipnsName)) {
      throw new NotFoundException('No cached record for this name');
    }
    const record = await this.cache.fetch(ipnsName);
    if (!record) {
      throw new NotFoundException('No cached record for this name');
    }
    return new StreamableFile(record, { type: IPNS_RECORD_MEDIA_TYPE });
  }
}

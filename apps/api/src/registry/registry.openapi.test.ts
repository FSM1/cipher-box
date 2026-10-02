import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../app-setup';
import { MAX_BATCH, MAX_CONTENT_CIDS } from './dto/registry.dto';
import { RegistryController } from './registry.controller';
import { RegistryService } from './services/registry.service';

type Schema = { maxItems?: number; properties?: Record<string, Schema> };

/** The batch bounds a client reads from the published document (blueprint/api.md "Batch bounds"). */
describe('registry OpenAPI bounds', () => {
  it('publishes every batch cap as maxItems', async () => {
    const moduleRef = await Test.createTestingModule({
      controllers: [RegistryController],
      providers: [
        { provide: RegistryService, useValue: {} },
        { provide: JwtService, useValue: {} },
        { provide: ConfigService, useValue: new ConfigService() },
      ],
    }).compile();
    const app = moduleRef.createNestApplication({ logger: false });
    try {
      const schemas = buildOpenApiDocument(app).components?.schemas as Record<string, Schema>;
      expect(schemas.RegisterEntryDto.properties?.contentCids.maxItems).toBe(MAX_CONTENT_CIDS);
      expect(schemas.RetireEntryDto.properties?.targets.maxItems).toBe(MAX_BATCH);
    } finally {
      await app.close();
    }
  });
});

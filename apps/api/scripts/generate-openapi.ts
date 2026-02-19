/**
 * OpenAPI spec generation script for CipherBox API.
 *
 * This script creates a minimal NestJS application context specifically
 * for generating the OpenAPI specification without requiring a live database.
 */
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

// Import controllers that define the API
import { AppController } from '../src/app.controller';
import { AppService } from '../src/app.service';
import { AuthController } from '../src/auth/auth.controller';
import { AuthService } from '../src/auth/auth.service';
import { Web3AuthVerifierService } from '../src/auth/services/web3auth-verifier.service';
import { TokenService } from '../src/auth/services/token.service';
import { JwtIssuerService } from '../src/auth/services/jwt-issuer.service';
import { GoogleOAuthService } from '../src/auth/services/google-oauth.service';
import { EmailOtpService } from '../src/auth/services/email-otp.service';
import { SiweService } from '../src/auth/services/siwe.service';
import { IdentityController } from '../src/auth/controllers/identity.controller';
import { IpfsController } from '../src/ipfs/ipfs.controller';
import { IPFS_PROVIDER } from '../src/ipfs/providers';
import { VaultController } from '../src/vault/vault.controller';
import { VaultService } from '../src/vault/vault.service';
import { IpnsController } from '../src/ipns/ipns.controller';
import { IpnsService } from '../src/ipns/ipns.service';
import { DeviceApprovalController } from '../src/device-approval/device-approval.controller';
import { DeviceApprovalService } from '../src/device-approval/device-approval.service';
import { MetricsService } from '../src/metrics/metrics.service';
import { User } from '../src/auth/entities/user.entity';
import { AuthMethod } from '../src/auth/entities/auth-method.entity';
import { RefreshToken } from '../src/auth/entities/refresh-token.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';

// Mock providers for OpenAPI generation - these won't be called
const mockRepository = {
  provide: getRepositoryToken(User),
  useValue: {},
};

const mockAuthMethodRepository = {
  provide: getRepositoryToken(AuthMethod),
  useValue: {},
};

const mockRefreshTokenRepository = {
  provide: getRepositoryToken(RefreshToken),
  useValue: {},
};

const mockJwtService = {
  provide: 'JwtService',
  useValue: { sign: () => '' },
};

const mockConfigService = {
  provide: ConfigService,
  useValue: { get: () => 'mock-value' },
};

// Minimal module for OpenAPI generation - no database connection needed
@Module({
  imports: [
    // ThrottlerModule is required because IpnsController uses ThrottlerGuard
    ThrottlerModule.forRoot([{ ttl: 60000, limit: 10 }]),
  ],
  controllers: [
    AppController,
    AuthController,
    IdentityController,
    IpfsController,
    VaultController,
    IpnsController,
    DeviceApprovalController,
  ],
  providers: [
    AppService,
    {
      provide: AuthService,
      useValue: {},
    },
    {
      provide: Web3AuthVerifierService,
      useValue: {},
    },
    {
      provide: TokenService,
      useValue: {},
    },
    {
      provide: JwtIssuerService,
      useValue: { getJwksData: () => ({ keys: [] }) },
    },
    {
      provide: GoogleOAuthService,
      useValue: {},
    },
    {
      provide: EmailOtpService,
      useValue: {},
    },
    {
      provide: SiweService,
      useValue: {},
    },
    {
      provide: IPFS_PROVIDER,
      useValue: {},
    },
    {
      provide: VaultService,
      useValue: {},
    },
    {
      provide: IpnsService,
      useValue: {},
    },
    {
      provide: DeviceApprovalService,
      useValue: {},
    },
    {
      provide: MetricsService,
      useValue: {},
    },
    mockRepository,
    mockAuthMethodRepository,
    mockRefreshTokenRepository,
    mockJwtService,
    mockConfigService,
  ],
})
class OpenApiGeneratorModule {}

async function generateOpenApiSpec() {
  // Create app without starting HTTP server
  const app = await NestFactory.create(OpenApiGeneratorModule, {
    logger: false,
  });

  const config = new DocumentBuilder()
    .setTitle('CipherBox API')
    .setDescription('Zero-knowledge encrypted cloud storage API')
    .setVersion('0.1.0')
    .addBearerAuth()
    .addTag('Health', 'Health check endpoints')
    .addTag('Root', 'API root endpoints')
    .addTag('Auth', 'Authentication endpoints')
    .addTag('Identity', 'CipherBox identity provider endpoints')
    .addTag('Vault', 'Vault management endpoints')
    .addTag('Files', 'File operations endpoints')
    .addTag('IPFS', 'IPFS relay endpoints')
    .addTag('IPNS', 'IPNS relay endpoints')
    .addTag('device-approval', 'Cross-device approval endpoints')
    .build();

  // Create document from the app
  const document = SwaggerModule.createDocument(app, config);

  // Manually add health endpoint to spec (since we can't inject the real controller
  // without TypeORM dependencies)
  document.paths['/health'] = {
    get: {
      operationId: 'HealthController_check',
      summary: 'Check API and database health',
      tags: ['Health'],
      responses: {
        '200': {
          description: 'Health check passed',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  status: { type: 'string', example: 'ok' },
                  info: {
                    type: 'object',
                    properties: {
                      database: {
                        type: 'object',
                        properties: {
                          status: { type: 'string', example: 'up' },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        '503': {
          description: 'Health check failed',
        },
      },
    },
  };

  // Ensure output directory exists
  const outputDir = join(__dirname, '..', '..', '..', 'packages', 'api-client');
  mkdirSync(outputDir, { recursive: true });

  const outputPath = join(outputDir, 'openapi.json');
  writeFileSync(outputPath, JSON.stringify(document, null, 2));

  console.log(`OpenAPI spec written to: ${outputPath}`);

  await app.close();
  process.exit(0);
}

generateOpenApiSpec().catch((error) => {
  console.error('Failed to generate OpenAPI spec:', error);
  process.exit(1);
});

/**
 * Emit the OpenAPI document from decorators to apps/api/openapi.json.
 *
 * The document is a committed docs artifact (blueprint/api.md, Contract and
 * clients) — never a build input, never fed to a client generator. CI's
 * openapi-freshness job regenerates it and fails on drift.
 *
 * A stub module (controllers real, providers inert) is enough: swagger
 * scans decorators and never invokes handlers, so no database is needed.
 */
import 'reflect-metadata';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildOpenApiDocument } from '../src/app-setup';
import { AuthController } from '../src/auth/auth.controller';
import { AuthService } from '../src/auth/services/auth.service';
import { TestAuthService } from '../src/auth/services/test-auth.service';
import { TokenService } from '../src/auth/services/token.service';
import { ContentController } from '../src/content/content.controller';
import { ContentService } from '../src/content/content.service';
import { DeviceApprovalSessionController } from '../src/device-approval/device-approval-session.controller';
import { DeviceApprovalController } from '../src/device-approval/device-approval.controller';
import { DeviceController } from '../src/device-approval/device.controller';
import { AccountDeviceService } from '../src/device-approval/services/account-device.service';
import { DeviceApprovalService } from '../src/device-approval/services/device-approval.service';
import { HealthController } from '../src/health/health.controller';
import { IdentityController } from '../src/auth/identity.controller';
import { IdentityExchangeService } from '../src/auth/services/identity-exchange.service';
import { IdentityTokenService } from '../src/auth/services/identity-token.service';
import { MailboxController } from '../src/mailbox/mailbox.controller';
import { MailboxService } from '../src/mailbox/services/mailbox.service';
import { MetricsController } from '../src/ops/metrics.controller';
import { MetricsService } from '../src/ops/metrics.service';
import { AccountController } from '../src/registry/account.controller';
import { RegistryController } from '../src/registry/registry.controller';
import { AccountService } from '../src/registry/services/account.service';
import { RegistryService } from '../src/registry/services/registry.service';
import { RecoveryController } from '../src/republisher/recovery.controller';
import { RecordCacheService } from '../src/republisher/services/record-cache.service';

@Module({
  controllers: [
    HealthController,
    MetricsController,
    AuthController,
    IdentityController,
    MailboxController,
    RegistryController,
    AccountController,
    ContentController,
    DeviceController,
    DeviceApprovalSessionController,
    DeviceApprovalController,
    RecoveryController,
  ],
  providers: [
    { provide: AuthService, useValue: {} },
    { provide: TestAuthService, useValue: {} },
    { provide: TokenService, useValue: {} },
    { provide: IdentityExchangeService, useValue: {} },
    { provide: IdentityTokenService, useValue: {} },
    { provide: MailboxService, useValue: {} },
    { provide: MetricsService, useValue: {} },
    { provide: RegistryService, useValue: {} },
    { provide: AccountService, useValue: {} },
    { provide: ContentService, useValue: {} },
    { provide: AccountDeviceService, useValue: {} },
    { provide: DeviceApprovalService, useValue: {} },
    { provide: RecordCacheService, useValue: {} },
    { provide: JwtService, useValue: {} },
    { provide: ConfigService, useValue: new ConfigService() },
  ],
})
class OpenApiStubModule {}

async function generate(): Promise<void> {
  const app = await NestFactory.create(OpenApiStubModule, { logger: false });
  const document = buildOpenApiDocument(app);

  const outputPath = join(__dirname, '..', 'openapi.json');
  writeFileSync(outputPath, JSON.stringify(document, null, 2) + '\n');

  console.log(`OpenAPI document written to ${outputPath}`);

  await app.close();
}

generate().catch((error) => {
  console.error('Failed to generate OpenAPI document:', error);
  process.exitCode = 1;
});

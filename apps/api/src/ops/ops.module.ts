import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import { HealthController } from '../health/health.controller';
import { AccountThrottlerGuard } from './account-throttler.guard';
import { MetricsController } from './metrics.controller';
import { MetricsInterceptor } from './metrics.interceptor';
import { MetricsService } from './metrics.service';

/**
 * Ops baseline: health stub, Prometheus metrics, and the WORKING global
 * throttler. The ThrottlerGuard is bound as APP_GUARD here — every route in
 * any app importing this module is rate-limited by the global default, with
 * per-surface tightening via @Throttle and explicit @SkipThrottle opt-outs
 * (health, metrics). v1's defect was decorators without an active guard.
 *
 * The guard is account-aware (AccountThrottlerGuard): authenticated routes
 * are keyed by the account so the mailbox's per-sender / per-recipient limits
 * are literal, while unauthenticated routes keep the IP tracker.
 */
@Module({
  imports: [
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => [
        {
          ttl: Number(configService.get('THROTTLE_TTL_MS') ?? 60_000),
          limit: Number(configService.get('THROTTLE_LIMIT') ?? 100),
        },
      ],
    }),
  ],
  controllers: [HealthController, MetricsController],
  providers: [
    MetricsService,
    { provide: APP_GUARD, useClass: AccountThrottlerGuard },
    { provide: APP_INTERCEPTOR, useClass: MetricsInterceptor },
  ],
  exports: [MetricsService],
})
export class OpsModule {}

import { Module, OnModuleInit } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule, buildJwtOptions } from '../auth/auth.module';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { isDisabled } from '../common/env-flag';
import { SchedulerModule } from '../common/scheduler.module';
import { WorkerScheduler } from '../common/worker-scheduler';
import { DeviceApprovalSessionController } from './device-approval-session.controller';
import { DeviceApprovalController } from './device-approval.controller';
import { DeviceController } from './device.controller';
import { AccountDevice } from './entities/account-device.entity';
import { DeviceApproval } from './entities/device-approval.entity';
import { AccountDeviceService } from './services/account-device.service';
import { DeviceApprovalService } from './services/device-approval.service';
import { DeviceApprovalSweepTask } from './tasks/device-approval-sweep.task';

/**
 * The device-approval slice (ADR 0009 D1): the account's device registry and the
 * bulletin-board rendezvous it makes verifiable. `AuthModule` is imported rather
 * than re-provided — see its `exports`.
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([AccountDevice, DeviceApproval]),
    AuthModule,
    SchedulerModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: buildJwtOptions,
    }),
  ],
  controllers: [DeviceController, DeviceApprovalSessionController, DeviceApprovalController],
  providers: [AccountDeviceService, DeviceApprovalService, DeviceApprovalSweepTask, JwtAuthGuard],
})
export class DeviceApprovalModule implements OnModuleInit {
  constructor(
    private readonly scheduler: WorkerScheduler,
    private readonly sweepTask: DeviceApprovalSweepTask,
    private readonly configService: ConfigService
  ) {}

  onModuleInit(): void {
    // Opt-out (default on) for deployments that run the sweep out of process.
    if (isDisabled(this.configService.get('DEVICE_APPROVAL_SWEEP_ENABLED'))) {
      return;
    }
    this.scheduler.register(this.sweepTask);
  }
}

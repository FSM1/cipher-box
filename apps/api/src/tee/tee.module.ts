import { Module, Logger, OnModuleInit } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { TeeKeyState } from './tee-key-state.entity';
import { TeeKeyRotationLog } from './tee-key-rotation-log.entity';
import { TeeKeyStateService } from './tee-key-state.service';
import { TeeService } from './tee.service';

@Module({
  imports: [TypeOrmModule.forFeature([TeeKeyState, TeeKeyRotationLog]), ConfigModule],
  providers: [TeeService, TeeKeyStateService],
  exports: [TeeService, TeeKeyStateService],
})
export class TeeModule implements OnModuleInit {
  private readonly logger = new Logger(TeeModule.name);

  constructor(private readonly teeService: TeeService) {}

  async onModuleInit(): Promise<void> {
    try {
      await this.teeService.initializeFromTee();
    } catch (error) {
      // Never crash the application if TEE is unavailable
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`TEE initialization failed (non-fatal): ${message}`);
    }
  }
}

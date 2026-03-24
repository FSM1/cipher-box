import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { PinMigration } from './migration.entity';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { MigrationService } from './migration.service';
import { MigrationController } from './migration.controller';
import { MigrationProcessor } from './migration.processor';

@Module({
  imports: [
    TypeOrmModule.forFeature([PinMigration, PinnedCid]),
    BullModule.registerQueue({ name: 'pin-migration' }),
  ],
  controllers: [MigrationController],
  providers: [MigrationService, MigrationProcessor],
  exports: [MigrationService],
})
export class MigrationModule {}

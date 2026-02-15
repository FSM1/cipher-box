import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DeviceApproval } from './device-approval.entity';
import { DeviceApprovalService } from './device-approval.service';
import { DeviceApprovalController } from './device-approval.controller';

@Module({
  imports: [TypeOrmModule.forFeature([DeviceApproval])],
  controllers: [DeviceApprovalController],
  providers: [DeviceApprovalService],
})
export class DeviceApprovalModule {}

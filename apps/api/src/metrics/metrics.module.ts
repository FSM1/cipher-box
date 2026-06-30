import { Module, Global } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MetricsService } from './metrics.service';
import { MetricsController } from './metrics.controller';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
import { User } from '../auth/entities/user.entity';
import { IpnsRepublishSchedule } from '../republish/republish-schedule.entity';

@Global()
@Module({
  imports: [TypeOrmModule.forFeature([PinnedCid, IpnsRecord, User, IpnsRepublishSchedule])],
  providers: [MetricsService],
  controllers: [MetricsController],
  exports: [MetricsService],
})
export class MetricsModule {}

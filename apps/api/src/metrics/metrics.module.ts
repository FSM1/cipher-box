import { Module, Global } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MetricsService } from './metrics.service';
import { MetricsController } from './metrics.controller';
import { PinnedCid } from '../vault/entities/pinned-cid.entity';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { User } from '../auth/entities/user.entity';
import { IpnsRepublishSchedule } from '../republish/republish-schedule.entity';

@Global()
@Module({
  imports: [TypeOrmModule.forFeature([PinnedCid, FolderIpns, User, IpnsRepublishSchedule])],
  providers: [MetricsService],
  controllers: [MetricsController],
  exports: [MetricsService],
})
export class MetricsModule {}

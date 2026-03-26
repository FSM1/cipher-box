import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { IpnsController } from './ipns.controller';
import { IpnsService } from './ipns.service';
import { DelegatedRoutingModule } from './delegated-routing.module';
import { FolderIpns } from './entities/folder-ipns.entity';
import { RepublishModule } from '../republish/republish.module';
import { SharesModule } from '../shares/shares.module';

@Module({
  imports: [
    DelegatedRoutingModule,
    SharesModule,
    TypeOrmModule.forFeature([FolderIpns]),
    forwardRef(() => RepublishModule),
  ],
  controllers: [IpnsController],
  providers: [IpnsService],
  exports: [IpnsService],
})
export class IpnsModule {}

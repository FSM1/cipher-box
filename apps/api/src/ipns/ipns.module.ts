import { Module, forwardRef } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { IpnsController } from './ipns.controller';
import { IpnsService } from './ipns.service';
import { FolderIpns } from './entities/folder-ipns.entity';
import { RepublishModule } from '../republish/republish.module';

@Module({
  imports: [
    ConfigModule,
    TypeOrmModule.forFeature([FolderIpns]),
    forwardRef(() => RepublishModule),
  ],
  controllers: [IpnsController],
  providers: [IpnsService],
  exports: [IpnsService],
})
export class IpnsModule {}

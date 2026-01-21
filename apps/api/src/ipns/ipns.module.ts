import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { IpnsController } from './ipns.controller';
import { IpnsService } from './ipns.service';
import { FolderIpns } from './entities/folder-ipns.entity';

@Module({
  imports: [ConfigModule, TypeOrmModule.forFeature([FolderIpns])],
  controllers: [IpnsController],
  providers: [IpnsService],
  exports: [IpnsService],
})
export class IpnsModule {}

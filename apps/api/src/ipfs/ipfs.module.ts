import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { IpfsService } from './ipfs.service';

@Module({
  imports: [ConfigModule],
  providers: [IpfsService],
  exports: [IpfsService],
})
export class IpfsModule {}

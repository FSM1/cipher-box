import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Share, ShareKey } from './entities';
import { User } from '../auth/entities/user.entity';
import { SharesController } from './shares.controller';
import { SharesService } from './shares.service';

@Module({
  imports: [TypeOrmModule.forFeature([Share, ShareKey, User])],
  controllers: [SharesController],
  providers: [SharesService],
  exports: [SharesService],
})
export class SharesModule {}

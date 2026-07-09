import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Share, ShareInvite } from './entities';
import { User } from '../auth/entities/user.entity';
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
import { SharesController } from './shares.controller';
import { InvitesController } from './invites.controller';
import { ShareInvitesController } from './share-invites.controller';
import { SharesService } from './shares.service';
import { ShareInviteService } from './share-invite.service';

@Module({
  imports: [TypeOrmModule.forFeature([Share, ShareInvite, User, IpnsRecord])],
  controllers: [SharesController, InvitesController, ShareInvitesController],
  providers: [SharesService, ShareInviteService],
  exports: [SharesService, ShareInviteService],
})
export class SharesModule {}

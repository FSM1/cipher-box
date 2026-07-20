import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { buildJwtOptions } from '../auth/auth.module';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { IdentityService } from '../auth/services/identity.service';
import { MailboxController } from './mailbox.controller';
import { MailboxMessage } from './entities/mailbox-message.entity';
import { MailboxService } from './services/mailbox.service';

/**
 * The mailbox slice (blueprint/api.md, Mailbox). Reads the users table for
 * the recipient-existence oracle and provides its own stateless
 * IdentityService for publicKey normalization. Route auth reuses the auth
 * slice's JwtAuthGuard and JWT configuration.
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([MailboxMessage, User]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: buildJwtOptions,
    }),
  ],
  controllers: [MailboxController],
  providers: [MailboxService, IdentityService, JwtAuthGuard],
})
export class MailboxModule {}

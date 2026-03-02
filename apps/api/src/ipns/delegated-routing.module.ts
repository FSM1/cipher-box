import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DelegatedRoutingClient } from './delegated-routing.client';

@Module({
  imports: [ConfigModule],
  providers: [DelegatedRoutingClient],
  exports: [DelegatedRoutingClient],
})
export class DelegatedRoutingModule {}

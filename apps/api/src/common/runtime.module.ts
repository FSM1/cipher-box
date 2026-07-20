import { Global, Module } from '@nestjs/common';
import { Clock, SystemClock } from './clock';
import { Entropy, SystemEntropy } from './entropy';

/** Real clock and entropy, injected once — tests substitute fakes. */
@Global()
@Module({
  providers: [
    { provide: Clock, useClass: SystemClock },
    { provide: Entropy, useClass: SystemEntropy },
  ],
  exports: [Clock, Entropy],
})
export class RuntimeModule {}

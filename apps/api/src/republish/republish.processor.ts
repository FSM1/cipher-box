import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { RepublishService } from './republish.service';

@Processor('republish')
export class RepublishProcessor extends WorkerHost {
  private readonly logger = new Logger(RepublishProcessor.name);

  constructor(private readonly republishService: RepublishService) {
    super();
  }

  async process(job: Job): Promise<void> {
    this.logger.log(`Republish job started: ${job.name} (id: ${job.id})`);

    try {
      const result = await this.republishService.processRepublishBatch();

      this.logger.log(
        `Republish job complete: processed=${result.processed}, succeeded=${result.succeeded}, failed=${result.failed}`
      );

      // If all entries failed and none succeeded, TEE might be down.
      // When TEE recovers, reactivate stale entries.
      if (result.processed > 0 && result.succeeded === 0 && result.failed === result.processed) {
        this.logger.warn('All republish entries failed. TEE worker may be unreachable.');
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Republish job failed: ${message}`);
      throw error; // Let BullMQ handle retry
    }
  }
}

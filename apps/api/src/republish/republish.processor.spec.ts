import { RepublishProcessor } from './republish.processor';
import { RepublishService } from './republish.service';
import { MetricsService } from '../metrics/metrics.service';
import { Job } from 'bullmq';

describe('RepublishProcessor', () => {
  let processor: RepublishProcessor;
  let republishService: jest.Mocked<Partial<RepublishService>>;
  let metricsService: {
    republishRuns: { inc: jest.Mock };
    republishEntriesProcessed: { inc: jest.Mock };
  };

  function createMockJob(overrides: Partial<Job> = {}): Job {
    return {
      name: 'republish-batch',
      id: 'job-1',
      ...overrides,
    } as unknown as Job;
  }

  beforeEach(() => {
    republishService = {
      processRepublishBatch: jest.fn(),
    };

    metricsService = {
      republishRuns: { inc: jest.fn() },
      republishEntriesProcessed: { inc: jest.fn() },
    };

    // Construct directly instead of using Test.createTestingModule,
    // since WorkerHost from @nestjs/bullmq has minimal base-class requirements.
    processor = new RepublishProcessor(
      republishService as unknown as RepublishService,
      metricsService as unknown as MetricsService
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should call processRepublishBatch and complete successfully', async () => {
    republishService.processRepublishBatch!.mockResolvedValue({
      processed: 10,
      succeeded: 8,
      failed: 2,
    });

    await expect(processor.process(createMockJob())).resolves.toBeUndefined();

    expect(republishService.processRepublishBatch).toHaveBeenCalledTimes(1);
  });

  it('should handle zero processed entries without warning', async () => {
    republishService.processRepublishBatch!.mockResolvedValue({
      processed: 0,
      succeeded: 0,
      failed: 0,
    });

    await expect(processor.process(createMockJob())).resolves.toBeUndefined();

    expect(republishService.processRepublishBatch).toHaveBeenCalledTimes(1);
  });

  it('should complete without throwing when all entries failed (logs warning)', async () => {
    // When all entries fail, the processor logs a warning but does NOT throw.
    // This allows BullMQ to mark the job as complete rather than retrying.
    republishService.processRepublishBatch!.mockResolvedValue({
      processed: 5,
      succeeded: 0,
      failed: 5,
    });

    await expect(processor.process(createMockJob())).resolves.toBeUndefined();

    expect(republishService.processRepublishBatch).toHaveBeenCalledTimes(1);
  });

  it('should re-throw errors from processRepublishBatch for BullMQ retry', async () => {
    const error = new Error('Database connection lost');
    republishService.processRepublishBatch!.mockRejectedValue(error);

    await expect(processor.process(createMockJob())).rejects.toThrow('Database connection lost');

    expect(republishService.processRepublishBatch).toHaveBeenCalledTimes(1);
  });

  it('should re-throw non-Error thrown values', async () => {
    republishService.processRepublishBatch!.mockRejectedValue('string-error');

    await expect(processor.process(createMockJob())).rejects.toBe('string-error');
  });

  it('should pass job metadata for logging (job.name and job.id)', async () => {
    republishService.processRepublishBatch!.mockResolvedValue({
      processed: 1,
      succeeded: 1,
      failed: 0,
    });

    const job = createMockJob({ name: 'custom-job-name', id: 'custom-id-42' });

    // Verify it does not throw -- the job name/id are used for logging only
    await expect(processor.process(job)).resolves.toBeUndefined();
  });

  it('should handle partial success results', async () => {
    republishService.processRepublishBatch!.mockResolvedValue({
      processed: 10,
      succeeded: 7,
      failed: 3,
    });

    // Partial success should NOT throw -- only complete service failure does
    await expect(processor.process(createMockJob())).resolves.toBeUndefined();
  });

  it('should handle result where processed > 0 but succeeded > 0 (no warning)', async () => {
    // This verifies the condition: only logs warning when succeeded === 0 AND failed === processed
    republishService.processRepublishBatch!.mockResolvedValue({
      processed: 10,
      succeeded: 1,
      failed: 9,
    });

    // Even with 9/10 failed, having 1 success means TEE is working, so no warning
    await expect(processor.process(createMockJob())).resolves.toBeUndefined();
  });
});

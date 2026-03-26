import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable, tap } from 'rxjs';
import { Request, Response } from 'express';
import { MetricsService } from './metrics.service';

@Injectable()
export class HttpMetricsInterceptor implements NestInterceptor {
  constructor(private readonly metricsService: MetricsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const httpContext = context.switchToHttp();
    const req = httpContext.getRequest<Request>();
    const startTime = process.hrtime.bigint();

    return next.handle().pipe(
      tap({
        next: () => {
          const res = httpContext.getResponse<Response>();
          this.recordDuration(req, res.statusCode, startTime);
        },
        error: (err: unknown) => {
          // Exception filters haven't run yet, so derive status from the exception
          const statusCode =
            err &&
            typeof err === 'object' &&
            'getStatus' in err &&
            typeof (err as { getStatus: unknown }).getStatus === 'function'
              ? (err as { getStatus: () => number }).getStatus()
              : 500;
          this.recordDuration(req, statusCode, startTime);
        },
      })
    );
  }

  private recordDuration(req: Request, statusCode: number, startTime: bigint): void {
    const matched = req.route?.path;

    // Unmatched routes (bot scanners, typos) get a single bucket to cap cardinality
    const route = matched ?? '/:unmatched';

    // Exclude /metrics endpoint to avoid self-referential noise
    if (route === '/metrics') return;

    const durationNs = Number(process.hrtime.bigint() - startTime);
    const durationSec = durationNs / 1e9;

    this.metricsService.httpRequestDuration
      .labels(req.method, route, String(statusCode))
      .observe(durationSec);
  }
}

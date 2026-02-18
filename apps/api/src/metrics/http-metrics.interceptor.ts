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
        error: () => {
          const res = httpContext.getResponse<Response>();
          // On error, statusCode may already be set by exception filter
          const statusCode = res.statusCode >= 400 ? res.statusCode : 500;
          this.recordDuration(req, statusCode, startTime);
        },
      })
    );
  }

  private recordDuration(req: Request, statusCode: number, startTime: bigint): void {
    const durationNs = Number(process.hrtime.bigint() - startTime);
    const durationSec = durationNs / 1e9;

    // Normalize route to avoid high-cardinality labels (e.g., /ipfs/:cid)
    const route = this.normalizeRoute(req.route?.path ?? req.path);

    this.metricsService.httpRequestDuration
      .labels(req.method, route, String(statusCode))
      .observe(durationSec);
  }

  private normalizeRoute(path: string): string {
    // Skip metrics endpoint to avoid self-referential noise
    if (path === '/metrics') return '/metrics';

    // Replace UUIDs and CIDs with placeholders to keep cardinality low
    return path
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ':id')
      .replace(/\/ipfs\/[a-zA-Z0-9]+/, '/ipfs/:cid')
      .replace(/\/ipns\/[a-zA-Z0-9]+/, '/ipns/:name');
  }
}

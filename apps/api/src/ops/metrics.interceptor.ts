import {
  CallHandler,
  ExecutionContext,
  HttpException,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { Observable, throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { MetricsService } from './metrics.service';

/** Records count + duration for every handled HTTP request. */
@Injectable()
export class MetricsInterceptor implements NestInterceptor {
  constructor(private readonly metricsService: MetricsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (context.getType() !== 'http') {
      return next.handle();
    }
    const request = context.switchToHttp().getRequest<Request & { route?: { path?: string } }>();
    const response = context.switchToHttp().getResponse<Response>();
    const method = request.method;
    // Use the route template (bounded cardinality), never the raw URL.
    const route = request.route?.path ?? 'unmatched';
    const startedAt = process.hrtime.bigint();

    const observe = (status: number): void => {
      const seconds = Number(process.hrtime.bigint() - startedAt) / 1e9;
      this.metricsService.observeRequest(method, route, status, seconds);
    };

    return next.handle().pipe(
      tap(() => observe(response.statusCode)),
      catchError((error: unknown) => {
        observe(error instanceof HttpException ? error.getStatus() : 500);
        return throwError(() => error);
      })
    );
  }
}

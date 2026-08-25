import {
  CallHandler,
  ExecutionContext,
  HttpException,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { AuthOutcome, MetricsService } from '../ops/metrics.service';
import { routeLabelFor } from '../ops/route-label';

/**
 * Attempt/outcome counts for the auth surface. A refused credential and a
 * broken dependency are the same 4xx-vs-5xx split the panels alert on, so they
 * are separate outcomes rather than one `failure`.
 */
@Injectable()
export class AuthMetricsInterceptor implements NestInterceptor {
  constructor(private readonly metricsService: MetricsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const route = routeLabelFor(context);
    const observe = (outcome: AuthOutcome): void =>
      this.metricsService.observeAuthAttempt(route, outcome);

    return next.handle().pipe(
      tap(() => observe('success')),
      catchError((error: unknown) => {
        observe(error instanceof HttpException && error.getStatus() < 500 ? 'rejected' : 'error');
        return throwError(() => error);
      })
    );
  }
}

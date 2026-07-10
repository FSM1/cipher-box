import { HttpMetricsInterceptor } from './http-metrics.interceptor';
import { MetricsService } from './metrics.service';
import { ExecutionContext, CallHandler, BadRequestException } from '@nestjs/common';
import { Observable, of, throwError } from 'rxjs';
import { Request, Response } from 'express';

// Derive HttpArgumentsHost from ExecutionContext rather than importing it directly —
// @nestjs/common does not re-export the interface type from its package root.
type HttpArgumentsHost = ReturnType<ExecutionContext['switchToHttp']>;

// Typed test doubles — narrow mocks instead of broad `any` casts, so the
// suite keeps compile-time guarantees and stays lint-clean.

function createRequest(method: string, routePath?: string): Request {
  const req: Pick<Request, 'method' | 'route'> = {
    method,
    route: routePath === undefined ? undefined : ({ path: routePath } as Request['route']),
  };
  return req as Request;
}

function createResponse(statusCode: number): Response {
  const res: Pick<Response, 'statusCode'> = { statusCode };
  return res as Response;
}

function createExecutionContext(req: Request, res?: Response): ExecutionContext {
  const httpHost: HttpArgumentsHost = {
    getRequest: <T = Request>() => req as unknown as T,
    getResponse: <T = Response>() => res as unknown as T,
    getNext: <T>() => undefined as unknown as T,
  };
  return {
    switchToHttp: () => httpHost,
  } as Partial<ExecutionContext> as ExecutionContext;
}

function createCallHandler(result: Observable<unknown>): CallHandler {
  return { handle: () => result };
}

describe('HttpMetricsInterceptor', () => {
  let interceptor: HttpMetricsInterceptor;
  let metricsService: MetricsService;
  let mockHttpRequestDuration: { labels: jest.Mock };
  let observeSpy: jest.Mock;

  beforeEach(() => {
    // Mock the histogram that records duration: labels() returns an object
    // exposing the observe spy the interceptor calls with the duration.
    observeSpy = jest.fn();
    mockHttpRequestDuration = {
      labels: jest.fn().mockReturnValue({ observe: observeSpy }),
    };

    // Create a mock MetricsService exposing only the histogram under test.
    metricsService = {
      httpRequestDuration: mockHttpRequestDuration,
    } as unknown as MetricsService;

    interceptor = new HttpMetricsInterceptor(metricsService);

    // Mock process.hrtime.bigint globally
    jest.spyOn(process.hrtime, 'bigint').mockImplementation(() => BigInt(0));
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  describe('HTTP request success path', () => {
    it('should record request duration with correct labels on successful response', (done) => {
      const mockContext = createExecutionContext(
        createRequest('GET', '/api/vault'),
        createResponse(200)
      );
      const mockNext = createCallHandler(of({}));

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        // Verify labels were called with correct method, route, and status code
        expect(mockHttpRequestDuration.labels).toHaveBeenCalledWith('GET', '/api/vault', '200');

        // Verify observe was called with a plausible duration (>= 0)
        expect(observeSpy).toHaveBeenCalled();
        const durationArg = observeSpy.mock.calls[0][0];
        expect(durationArg).toBeGreaterThanOrEqual(0);
        expect(typeof durationArg).toBe('number');

        done();
      });
    });

    it('should exclude /metrics endpoint from recording', (done) => {
      const mockContext = createExecutionContext(
        createRequest('GET', '/metrics'),
        createResponse(200)
      );
      const mockNext = createCallHandler(of({}));

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        // /metrics should NOT be recorded
        expect(mockHttpRequestDuration.labels).not.toHaveBeenCalled();

        done();
      });
    });

    it('should record unmatched routes as /:unmatched', (done) => {
      const mockContext = createExecutionContext(
        createRequest('POST', undefined), // No matched route
        createResponse(404)
      );
      const mockNext = createCallHandler(of({}));

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        // Unmatched routes should be labeled as /:unmatched
        expect(mockHttpRequestDuration.labels).toHaveBeenCalledWith('POST', '/:unmatched', '404');

        done();
      });
    });
  });

  describe('HTTP request error path', () => {
    it('should record request duration on NestJS exception with getStatus', (done) => {
      const mockContext = createExecutionContext(createRequest('DELETE', '/api/files/:id'));
      const mockNext = createCallHandler(
        throwError(() => new BadRequestException('Invalid input'))
      );

      interceptor.intercept(mockContext, mockNext).subscribe({
        error: () => {
          // Verify error status code (400) was recorded
          expect(mockHttpRequestDuration.labels).toHaveBeenCalledWith(
            'DELETE',
            '/api/files/:id',
            '400'
          );

          done();
        },
      });
    });

    it('should default to 500 status code for unrecognized exceptions', (done) => {
      const mockContext = createExecutionContext(createRequest('PUT', '/api/vault/update'));
      // Plain Error object without getStatus
      const mockNext = createCallHandler(throwError(() => new Error('Database connection failed')));

      interceptor.intercept(mockContext, mockNext).subscribe({
        error: () => {
          // Should default to 500
          expect(mockHttpRequestDuration.labels).toHaveBeenCalledWith(
            'PUT',
            '/api/vault/update',
            '500'
          );

          done();
        },
      });
    });

    it('should handle null exception gracefully (default to 500)', (done) => {
      const mockContext = createExecutionContext(createRequest('GET', '/api/health'));
      const mockNext = createCallHandler(throwError(() => null));

      interceptor.intercept(mockContext, mockNext).subscribe({
        error: () => {
          // null exception should default to 500
          expect(mockHttpRequestDuration.labels).toHaveBeenCalledWith('GET', '/api/health', '500');

          done();
        },
      });
    });
  });

  describe('Duration calculation', () => {
    it('should calculate duration in seconds from nanoseconds', (done) => {
      const mockContext = createExecutionContext(
        createRequest('POST', '/api/login'),
        createResponse(200)
      );
      const mockNext = createCallHandler(of({}));

      // Simulate 250 milliseconds duration (250_000_000 nanoseconds)
      const startNs = BigInt(1000_000_000);
      const endNs = BigInt(1250_000_000); // 250ms later
      let callCount = 0;

      (process.hrtime.bigint as jest.Mock).mockImplementation(() => {
        callCount++;
        return callCount === 1 ? startNs : endNs;
      });

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        const duration = observeSpy.mock.calls[0][0];

        // Should be 0.25 seconds (250ms)
        expect(duration).toBeCloseTo(0.25, 2);

        done();
      });
    });

    it('should record very small durations (microseconds)', (done) => {
      const mockContext = createExecutionContext(
        createRequest('GET', '/api/ping'),
        createResponse(200)
      );
      const mockNext = createCallHandler(of({}));

      // Simulate 100 nanoseconds (0.0000001 seconds)
      const startNs = BigInt(1000);
      const endNs = BigInt(1100);
      let callCount = 0;

      (process.hrtime.bigint as jest.Mock).mockImplementation(() => {
        callCount++;
        return callCount === 1 ? startNs : endNs;
      });

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        const duration = observeSpy.mock.calls[0][0];

        // Should be 100e-9 seconds = 0.0000001
        expect(duration).toBeGreaterThanOrEqual(0);
        expect(duration).toBeLessThan(0.001); // Small duration

        done();
      });
    });
  });

  describe('Various HTTP methods', () => {
    ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].forEach((method) => {
      it(`should record ${method} requests correctly`, (done) => {
        const mockContext = createExecutionContext(
          createRequest(method, '/api/resource'),
          createResponse(200)
        );
        const mockNext = createCallHandler(of({}));

        interceptor.intercept(mockContext, mockNext).subscribe(() => {
          expect(mockHttpRequestDuration.labels).toHaveBeenCalledWith(
            method,
            '/api/resource',
            '200'
          );

          done();
        });
      });
    });
  });

  describe('Various HTTP status codes', () => {
    [200, 201, 204, 400, 401, 403, 404, 500, 502, 503].forEach((status) => {
      it(`should record ${status} status code correctly`, (done) => {
        const mockContext = createExecutionContext(
          createRequest('GET', '/api/test'),
          createResponse(status)
        );
        const mockNext = createCallHandler(of({}));

        interceptor.intercept(mockContext, mockNext).subscribe(() => {
          expect(mockHttpRequestDuration.labels).toHaveBeenCalledWith(
            'GET',
            '/api/test',
            String(status)
          );

          done();
        });
      });
    });
  });
});

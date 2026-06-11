import { HttpMetricsInterceptor } from './http-metrics.interceptor';
import { MetricsService } from './metrics.service';
import { ExecutionContext, CallHandler } from '@nestjs/common';
import { BadRequestException } from '@nestjs/common';
import { of, throwError } from 'rxjs';
import { Request, Response } from 'express';

describe('HttpMetricsInterceptor', () => {
  let interceptor: HttpMetricsInterceptor;
  let metricsService: MetricsService;
  let mockHttpRequestDuration: any;

  beforeEach(() => {
    // Mock the histogram that records duration
    mockHttpRequestDuration = {
      labels: jest.fn().mockReturnValue({
        observe: jest.fn(),
      }),
    };

    // Create a mock MetricsService
    metricsService = {
      httpRequestDuration: mockHttpRequestDuration,
    } as any;

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
      const mockRequest = {
        method: 'GET',
        route: {
          path: '/api/vault',
        },
      } as any as Request;

      const mockResponse = {
        statusCode: 200,
      } as any as Response;

      const mockContext = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
          getResponse: jest.fn().mockReturnValue(mockResponse),
        }),
      } as any as ExecutionContext;

      const mockNext = {
        handle: jest.fn().mockReturnValue(of({})),
      } as any as CallHandler;

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        // Verify labels were called with correct method, route, and status code
        expect(mockHttpRequestDuration.labels).toHaveBeenCalledWith('GET', '/api/vault', '200');

        // Verify observe was called with a plausible duration (>= 0)
        const observeCall = mockHttpRequestDuration.labels().observe;
        expect(observeCall).toHaveBeenCalled();
        const durationArg = observeCall.mock.calls[0][0];
        expect(durationArg).toBeGreaterThanOrEqual(0);
        expect(typeof durationArg).toBe('number');

        done();
      });
    });

    it('should exclude /metrics endpoint from recording', (done) => {
      const mockRequest = {
        method: 'GET',
        route: {
          path: '/metrics',
        },
      } as any as Request;

      const mockResponse = {
        statusCode: 200,
      } as any as Response;

      const mockContext = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
          getResponse: jest.fn().mockReturnValue(mockResponse),
        }),
      } as any as ExecutionContext;

      const mockNext = {
        handle: jest.fn().mockReturnValue(of({})),
      } as any as CallHandler;

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        // /metrics should NOT be recorded
        expect(mockHttpRequestDuration.labels).not.toHaveBeenCalled();

        done();
      });
    });

    it('should record unmatched routes as /:unmatched', (done) => {
      const mockRequest = {
        method: 'POST',
        route: undefined, // No matched route
      } as any as Request;

      const mockResponse = {
        statusCode: 404,
      } as any as Response;

      const mockContext = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
          getResponse: jest.fn().mockReturnValue(mockResponse),
        }),
      } as any as ExecutionContext;

      const mockNext = {
        handle: jest.fn().mockReturnValue(of({})),
      } as any as CallHandler;

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        // Unmatched routes should be labeled as /:unmatched
        expect(mockHttpRequestDuration.labels).toHaveBeenCalledWith('POST', '/:unmatched', '404');

        done();
      });
    });
  });

  describe('HTTP request error path', () => {
    it('should record request duration on NestJS exception with getStatus', (done) => {
      const mockRequest = {
        method: 'DELETE',
        route: {
          path: '/api/files/:id',
        },
      } as any as Request;

      const mockContext = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
          getResponse: jest.fn(),
        }),
      } as any as ExecutionContext;

      const testError = new BadRequestException('Invalid input');
      const mockNext = {
        handle: jest.fn().mockReturnValue(throwError(() => testError)),
      } as any as CallHandler;

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
      const mockRequest = {
        method: 'PUT',
        route: {
          path: '/api/vault/update',
        },
      } as any as Request;

      const mockContext = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
          getResponse: jest.fn(),
        }),
      } as any as ExecutionContext;

      // Plain Error object without getStatus
      const testError = new Error('Database connection failed');
      const mockNext = {
        handle: jest.fn().mockReturnValue(throwError(() => testError)),
      } as any as CallHandler;

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
      const mockRequest = {
        method: 'GET',
        route: {
          path: '/api/health',
        },
      } as any as Request;

      const mockContext = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
          getResponse: jest.fn(),
        }),
      } as any as ExecutionContext;

      const mockNext = {
        handle: jest.fn().mockReturnValue(throwError(() => null)),
      } as any as CallHandler;

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
      const mockRequest = {
        method: 'POST',
        route: {
          path: '/api/login',
        },
      } as any as Request;

      const mockResponse = {
        statusCode: 200,
      } as any as Response;

      const mockContext = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
          getResponse: jest.fn().mockReturnValue(mockResponse),
        }),
      } as any as ExecutionContext;

      const mockNext = {
        handle: jest.fn().mockReturnValue(of({})),
      } as any as CallHandler;

      // Simulate 250 milliseconds duration (250_000_000 nanoseconds)
      const startNs = BigInt(1000_000_000);
      const endNs = BigInt(1250_000_000); // 250ms later
      let callCount = 0;

      (process.hrtime.bigint as jest.Mock).mockImplementation(() => {
        callCount++;
        return callCount === 1 ? startNs : endNs;
      });

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        const observeCall = mockHttpRequestDuration.labels().observe;
        const duration = observeCall.mock.calls[0][0];

        // Should be 0.25 seconds (250ms)
        expect(duration).toBeCloseTo(0.25, 2);

        done();
      });
    });

    it('should record very small durations (microseconds)', (done) => {
      const mockRequest = {
        method: 'GET',
        route: {
          path: '/api/ping',
        },
      } as any as Request;

      const mockResponse = {
        statusCode: 200,
      } as any as Response;

      const mockContext = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
          getResponse: jest.fn().mockReturnValue(mockResponse),
        }),
      } as any as ExecutionContext;

      const mockNext = {
        handle: jest.fn().mockReturnValue(of({})),
      } as any as CallHandler;

      // Simulate 100 nanoseconds (0.0000001 seconds)
      const startNs = BigInt(1000);
      const endNs = BigInt(1100);
      let callCount = 0;

      (process.hrtime.bigint as jest.Mock).mockImplementation(() => {
        callCount++;
        return callCount === 1 ? startNs : endNs;
      });

      interceptor.intercept(mockContext, mockNext).subscribe(() => {
        const observeCall = mockHttpRequestDuration.labels().observe;
        const duration = observeCall.mock.calls[0][0];

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
        const mockRequest = {
          method,
          route: {
            path: '/api/resource',
          },
        } as any as Request;

        const mockResponse = {
          statusCode: 200,
        } as any as Response;

        const mockContext = {
          switchToHttp: jest.fn().mockReturnValue({
            getRequest: jest.fn().mockReturnValue(mockRequest),
            getResponse: jest.fn().mockReturnValue(mockResponse),
          }),
        } as any as ExecutionContext;

        const mockNext = {
          handle: jest.fn().mockReturnValue(of({})),
        } as any as CallHandler;

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
        const mockRequest = {
          method: 'GET',
          route: {
            path: '/api/test',
          },
        } as any as Request;

        const mockResponse = {
          statusCode: status,
        } as any as Response;

        const mockContext = {
          switchToHttp: jest.fn().mockReturnValue({
            getRequest: jest.fn().mockReturnValue(mockRequest),
            getResponse: jest.fn().mockReturnValue(mockResponse),
          }),
        } as any as ExecutionContext;

        const mockNext = {
          handle: jest.fn().mockReturnValue(of({})),
        } as any as CallHandler;

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

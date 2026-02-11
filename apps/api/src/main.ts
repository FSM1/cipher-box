import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe, Logger } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function bootstrap() {
  const isDev = process.env.NODE_ENV === 'development' || !process.env.NODE_ENV;

  // In staging/production, omit debug and verbose log levels for concise output
  const app = await NestFactory.create(AppModule, {
    logger: isDev ? ['log', 'error', 'warn', 'debug', 'verbose'] : ['log', 'error', 'warn'],
  });

  const logger = new Logger('Bootstrap');

  // [SECURITY: CRITICAL-01] Enable global validation pipe
  // Without this, all DTO validation decorators (@IsString, @Matches, etc.) are ignored
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Strip properties not in DTO
      forbidNonWhitelisted: true, // Reject unexpected properties
      transform: true, // Auto-transform types
    })
  );

  app.use(cookieParser());

  // CORS_ALLOWED_ORIGINS supports wildcards (e.g. https://cipher-box-pr-*.onrender.com)
  // Falls back to WEB_APP_URL for backwards compatibility
  const rawOrigins = process.env.CORS_ALLOWED_ORIGINS || process.env.WEB_APP_URL;
  const originEntries = rawOrigins
    ? rawOrigins.split(',').map((s) => s.trim())
    : ['http://localhost:5173', 'http://localhost:4173'];
  const exactOrigins = originEntries.filter((o) => !o.includes('*'));
  const wildcardPatterns = originEntries
    .filter((o) => o.includes('*'))
    .map((o) => new RegExp(`^${o.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`));

  app.enableCors({
    origin: (
      origin: string | undefined,
      callback: (err: Error | null, allow?: boolean) => void
    ) => {
      if (!origin) return callback(null, true);
      if (exactOrigins.includes(origin)) return callback(null, true);
      if (wildcardPatterns.some((re) => re.test(origin))) return callback(null, true);
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    },
    credentials: true,
  });

  const config = new DocumentBuilder()
    .setTitle('CipherBox API')
    .setDescription('Zero-knowledge encrypted cloud storage API')
    .setVersion('0.1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document, {
    jsonDocumentUrl: 'api-docs/json',
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  logger.log(`CipherBox API running on http://localhost:${port}`);
  logger.log(`Swagger UI: http://localhost:${port}/api-docs`);
}
bootstrap();

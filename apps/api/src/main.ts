import 'reflect-metadata';
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { SwaggerModule } from '@nestjs/swagger';
import { buildOpenApiDocument, configureApp, corsOptionsFromEnv } from './app-setup';
import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
  const isDev = process.env.NODE_ENV === 'development' || !process.env.NODE_ENV;
  const app = await NestFactory.create(AppModule, {
    logger: isDev ? ['log', 'error', 'warn', 'debug', 'verbose'] : ['log', 'error', 'warn'],
  });
  const logger = new Logger('Bootstrap');

  configureApp(app);
  app.enableCors(corsOptionsFromEnv(process.env.CORS_ALLOWED_ORIGINS));

  const document = buildOpenApiDocument(app);
  SwaggerModule.setup('api-docs', app, document, { jsonDocumentUrl: 'api-docs/json' });

  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);
  logger.log(`CipherBox API listening on http://localhost:${port}`);
}

void bootstrap();

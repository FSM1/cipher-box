import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

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
  app.enableCors({
    origin: process.env.WEB_APP_URL
      ? process.env.WEB_APP_URL.split(',')
      : ['http://localhost:5173', 'http://localhost:4173'],
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

  await app.listen(3000);
  console.log('CipherBox API running on http://localhost:3000');
  console.log('Swagger UI: http://localhost:3000/api-docs');
}
bootstrap();

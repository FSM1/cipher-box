import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors();

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

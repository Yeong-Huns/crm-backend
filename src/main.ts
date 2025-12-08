import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { initializeTransactionalContext } from 'typeorm-transactional';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  initializeTransactionalContext();
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.enableCors({
    origin: ['http://localhost:5174'],
    credentials: true,
  });
  app.useGlobalPipes(
    new ValidationPipe({
      /* 정의되지 않은 프로퍼티 받지 않음 */
      whitelist: true,
      /* 정의되지 않은 프로퍼티로 요청보내면 오류던짐 */
      forbidNonWhitelisted: true,
      /* 타입스크립트 타입을 보고 해당 타입으로 자동 변환 */
      transformOptions: { enableImplicitConversion: true },
      transform: true,
    }),
  );

  const config = new DocumentBuilder()
    .setTitle('seesaw ind student')
    .setDescription('유학생 서류접수 시스템')
    .setVersion('1.0')
    .addTag('seesaw')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'access-token',
        description: 'access token',
        in: 'header',
      },
      'access-token',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  await app.listen(process.env.PORT ?? 3009);
}
bootstrap();

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { initializeTransactionalContext } from 'typeorm-transactional';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  initializeTransactionalContext();
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.useGlobalPipes(
    new ValidationPipe({
      /* 정의되지 않은 프로퍼티 받지 않음 */
      whitelist: true,
      /* 정의되지 않은 프로퍼티로 요청보내면 오류던짐 */
      forbidNonWhitelisted: true,
      /* 타입스크립트 타입을 보고 해당 타입으로 자동 변환 */
      transformOptions: { enableImplicitConversion: true },
    }),
  );
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();

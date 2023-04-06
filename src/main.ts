import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { AuthGuard } from './auth.guard';
import { ValidationPipe } from './validation.pipe';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { DelayInterceptor } from './delay.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalInterceptors(new DelayInterceptor());
  app.useGlobalPipes(new ValidationPipe());
  app.useGlobalGuards(new AuthGuard());

  const config = new DocumentBuilder()
    .setTitle('Cats example')
    .setDescription('The cats API description')
    .setVersion('0.1')
    .addTag('Cats Tag')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
  await app.listen(3000);
}
bootstrap();

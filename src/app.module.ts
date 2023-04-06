import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { CatsModule } from './cats/cats.module';
import { LoggerMiddleware } from './cats/logger.middleware';
import { PostMiddleware } from './cats/post.middleware';
import { User } from './users/entities/user.entity';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    CatsModule,
    TypeOrmModule.forRoot({
      type: 'mssql',
      host: 'localhost',
      port: 1433,
      username: 'ysUser',
      password: 'PasswordAdmin123',
      database: 'testing',
      entities: [User],
      extra: {
        trustServerCertificate: true,
      },
      // entities: ['dist/**/*.entity.js'],
      // autoLoadEntities: true,
      synchronize: true,
    }),
    UsersModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // consumer.apply(LoggerMiddleware).forRoutes('cats');
    consumer
      .apply(LoggerMiddleware)
      .exclude({ path: 'cats', method: RequestMethod.POST })
      .forRoutes({ path: 'cats', method: RequestMethod.ALL });
    consumer
      .apply(PostMiddleware)
      .forRoutes({ path: 'cats', method: RequestMethod.POST });
  }
}

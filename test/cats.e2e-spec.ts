import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { CatsController } from '../src/cats/cats.controller';
import { CatsService } from '../src/cats/cats.service';
import * as request from 'supertest';
import { AuthGuard } from '../src/auth.guard';
import { ValidationPipe } from '../src/validation.pipe';

describe('CatsController', () => {
  let app: INestApplication;

  // Define variables
  let catsService: CatsService;

  // Create test module
  beforeAll(async () => {
    // Compile module
    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [CatsController],
      providers: [CatsService],
    }).compile();
    // Retrive instances
    catsService = moduleRef.get<CatsService>(CatsService);

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    app.useGlobalGuards(new AuthGuard());
    await app.init();
  });

  it(`/GET cats`, () => {
    const token = 'MiMiCx1';
    return request(app.getHttpServer())
      .get('/cats')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect({
        data: catsService.findAll(),
      });
  });

  it(`/GET cats?id=1`, () => {
    const token = 'MiMiCx1';
    return request(app.getHttpServer())
      .get('/cats?id=1')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect({
        data: catsService.findOneById(1),
      });
  });

  afterAll(async () => {
    await app.close();
  });
});

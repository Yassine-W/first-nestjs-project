import { Test, TestingModule } from '@nestjs/testing';
import { CatsController } from './cats.controller';
import { CatsService } from './cats.service';
import { Cat } from './interfaces/cat.interface';

describe('CatsController', () => {
  // Define variables
  // let catsController: CatsController;
  let catsService: CatsService;

  // Create test module
  beforeEach(async () => {
    // Compile module
    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [CatsController],
      providers: [CatsService],
    }).compile();
    // Retrive instances
    catsService = moduleRef.get<CatsService>(CatsService);
    // catsController = moduleRef.get<CatsController>(CatsController);

    // catsService = await moduleRef.resolve(CatsService);
    // catsController = await moduleRef.resolve(CatsController);
  });

  describe('findAll', () => {
    it('should return an array of cats', async () => {
      const result = [{ name: 'cat1', age: 3, breed: 'string' } as Cat];
      jest.spyOn(catsService, 'findAll').mockImplementation(() => result);

      expect(catsService.findAll()).toEqual(result);
    });
  });
});

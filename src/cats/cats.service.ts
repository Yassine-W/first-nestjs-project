import { Injectable } from '@nestjs/common';
import { CreateCatDto } from './dto/create-cat.dto';
import { Cat } from './interfaces/cat.interface';

@Injectable()
export class CatsService {
  create(createCatDto: CreateCatDto) {
    return createCatDto;
  }

  findAll() {
    return [{ name: 'cat1', age: 3, breed: 'string' } as Cat];
  }

  findOne(id: number) {
    return { id };
  }

  findOneById(id: number) {
    const response = { msg: 'found by id', id };
    console.log(response);
    return response;
  }
}

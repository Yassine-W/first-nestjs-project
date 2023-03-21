import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  ParseIntPipe,
  Query,
  UseGuards,
} from '@nestjs/common';
import { Roles } from 'src/roles.decorator';
import { RolesGuard } from 'src/roles.guard';
import { CatsService } from './cats.service';
import { CreateCatDto } from './dto/create-cat.dto';

@Controller('cats')
@UseGuards(RolesGuard)
export class CatsController {
  constructor(private catsService: CatsService) {}

  @Post()
  @Roles('admin')
  async create(@Body() createCatDto: CreateCatDto) {
    return this.catsService.create(createCatDto);
  }

  @Get(':id')
  async findOne(@Param('id', ParseIntPipe) id: number) {
    return this.catsService.findOne(id);
  }

  @Get()
  async findOneById(@Query('id') id?: number) {
    if (id != null) {
      return this.catsService.findOneById(id);
    } else {
      return this.catsService.findAll();
    }
  }
}

// import {
//   Body,
//   Controller,
//   Get,
//   // Header,
//   // HttpCode,
//   Param,
//   Post,
//   Redirect,
// } from '@nestjs/common';
// import { CreateCatDto } from './create-cat.dto';

// @Controller('cats')
// // @Controller({ host: 'localhost:3000', path: 'cats' })
// export class CatsController {
//   //   @Post()
//   //   @Header('custom-header', 'none')
//   //   @HttpCode(204)
//   //   create(): string {
//   //     return 'This action adds a new cat';
//   //   }

//   @Post()
//   async create(@Body() createCatDto: CreateCatDto) {
//     console.log(createCatDto);
//     return `This action adds a new cat ${createCatDto.name}`;
//   }

//   @Get()
//   findAll(): string {
//     return 'This action returns all cats';
//   }

//   @Get('ab*cd')
//   wildcardHandler() {
//     return 'This route uses a wildcard';
//   }

//   @Get('mine')
//   @Redirect('http://localhost:3000/cats/ab*cd', 301)
//   handleMine() {
//     return {
//       url: 'http://localhost:3000/cats',
//       statusCode: 200,
//     };
//   }

//   @Get('/mine:id')
//   mineId(@Param('id') id: number): string {
//     console.log(id);
//     return `This action returns a #${id} cat`;
//   }

//   @Get(':id')
//   findOne(@Param() params): string {
//     console.log(params.id);
//     return `This action returns a #${params.id} cat`;
//   }
// }

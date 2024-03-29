import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  ParseIntPipe,
  Query,
  UseGuards,
  UseInterceptors,
  Ip,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiHeader,
  ApiTags,
} from '@nestjs/swagger';
import { DelayInterceptor } from '../delay.interceptor';
import { LoggingInterceptor } from '../logging.interceptor';
import { Roles } from '../roles.decorator';
import { RolesGuard } from '../roles.guard';
import { User } from '../user.decorator';
import { CatsService } from './cats.service';
import { CreateCatDto } from './dto/create-cat.dto';
@ApiTags('cats routes')
@ApiHeader({
  name: 'X-MyHeader',
  description: 'Custom header',
})
@ApiBearerAuth()
@Controller('cats')
@UseGuards(RolesGuard)
@UseInterceptors(LoggingInterceptor, DelayInterceptor)
export class CatsController {
  constructor(private catsService: CatsService) {}

  @Post()
  @ApiCreatedResponse({
    description: 'The record has been successfully created.',
    type: CreateCatDto,
  })
  @Roles('admin')
  async create(@Body() createCatDto: CreateCatDto) {
    return this.catsService.create(createCatDto);
  }

  @Get(':id')
  async findOne(@Param('id', ParseIntPipe) id: number) {
    return this.catsService.findOne(id);
  }

  // @Get()
  // findAll() {
  //   return this.catsService.findAll();
  // }

  @Get()
  async findOneById(
    @Query('id') idStr: string,
    @Ip() ip: string,
    @User() user: any,
  ) {
    console.log('Client IP From controller:', ip);
    console.log('User From controller:', user);
    if (idStr != null) {
      const id = Number(idStr);
      return this.catsService.findOneById(parseInt(`${id}`));
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

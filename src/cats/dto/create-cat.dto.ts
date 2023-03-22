import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsString, IsNumber, IsOptional } from 'class-validator';

export class CreateCatDto {
  @ApiProperty({ description: `A name for the cat`, example: 'My cat' })
  @IsString()
  name: string;

  @ApiProperty({
    description: 'The age of the cat',
    minimum: 0,
    default: 0,
  })
  @IsNumber()
  @Type(() => Number)
  age: number;

  @ApiProperty({ required: false })
  @IsString()
  @IsOptional()
  breed: string;
}

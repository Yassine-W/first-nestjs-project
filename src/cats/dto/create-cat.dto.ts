import { Type } from 'class-transformer';
import { IsString, IsNumber, IsOptional } from 'class-validator';

export class CreateCatDto {
  @IsString()
  name: string;

  @IsNumber()
  @Type(() => Number)
  age: number;

  @IsString()
  @IsOptional()
  breed: string;
}

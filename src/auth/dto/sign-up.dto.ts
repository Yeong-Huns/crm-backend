import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsNumber,
  IsString,
  MinLength,
} from 'class-validator';

export class SignUpDto {
  @ApiProperty({ description: '이메일', example: 'test@naver.com' })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ description: '비밀번호', example: 'qwer1234' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ description: '이름', example: '홍길동' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: '국가코드' })
  @IsNumber()
  @IsNotEmpty()
  country: number;

  @ApiProperty({ description: '조직코드' })
  @IsNumber()
  @IsNotEmpty()
  organization: number;

  @ApiProperty({ description: '주소', example: '서울 강남구' })
  @IsString()
  @IsNotEmpty()
  address: string;

  @ApiProperty({ description: '권한 ID', example: 2 })
  @IsNumber()
  role: number;

  @ApiProperty({ description: '가입 상태 ID', example: 1 })
  @IsNumber()
  registrationStatus: number;
}

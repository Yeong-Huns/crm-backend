import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class SignInDto {
  @ApiProperty({
    description: '관리자 로그인 이메일 ',
    example: 'qqqq@naver.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ description: '관리자 로그인 비밀번호', example: 'qwer1234' })
  @MinLength(6)
  @IsString()
  password: string;
}

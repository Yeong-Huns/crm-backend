import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  Res,
  UseInterceptors,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './decorator/public.decorator';
import { TokenPayload } from './const/auth.const';
import type { Request as ExpressRequest, Response } from 'express';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { Refresh } from './decorator/refresh.decorator';
import { Role } from './decorator/role-based-access-control.decorator';
import { UserRole } from '../user/type/user.role';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';

interface TokenRequest extends ExpressRequest {
  user: TokenPayload;
}

@ApiTags('인증/인가')
@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('sign-up')
  @ApiOperation({
    summary: '회원가입',
    description: '새로운 사용자를 등록합니다.',
  })
  @ApiResponse({ status: 201, description: '회원가입 성공 (User 객체 반환)' })
  @ApiResponse({
    status: 400,
    description: '입력 데이터 유효성 검사 실패 또는 이메일 중복',
  })
  registerUser(@Body() signUpDto: SignUpDto) {
    return this.authService.registerUser(signUpDto);
  }

  @Public()
  @Post('sign-in')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: '로그인',
    description: '이메일과 비밀번호로 로그인하고 Access Token을 발급받습니다.',
  })
  @ApiResponse({
    status: 200,
    description: '로그인 성공 (Access Token 반환 및 Refresh Token 쿠키 설정)',
  })
  @ApiResponse({ status: 401, description: '인증 실패 (비밀번호 불일치 등)' })
  async loginUser(
    @Res({ passthrough: true }) res: Response,
    @Body() signInDto: SignInDto,
  ) {
    return await this.authService.login(signInDto, res);
  }

  @Refresh()
  @Post('token/access')
  @HttpCode(HttpStatus.OK)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('refresh-token')
  @ApiOperation({
    summary: 'Access Token 재발급',
    description: 'Refresh Token을 사용하여 새로운 Access Token을 발급받습니다.',
  })
  @ApiResponse({ status: 200, description: '재발급 성공' })
  @ApiResponse({
    status: 401,
    description: 'Refresh Token이 유효하지 않거나 만료됨',
  })
  async rotateAccessToken(@Request() req: TokenRequest) {
    const { sub, role } = req.user;
    const accessToken = await this.authService.issueAccessToken({
      id: sub,
      role: role,
    });
    return { accessToken };
  }

  /* 테스트용 */
  @Role(UserRole.SUPERVISOR)
  @Get('private')
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: '관리자 전용 테스트 API',
    description: 'SUPERVISOR 권한을 가진 사용자만 접근 가능합니다.',
  })
  @ApiResponse({ status: 200, description: '접근 성공' })
  @ApiResponse({ status: 403, description: '권한 부족 (Forbidden)' })
  private(@Request() request: TokenRequest) {
    return request.user;
  }

  @Get('me')
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: '내 정보 조회',
    description: '현재 로그인한 사용자의 정보를 조회합니다.',
  })
  @ApiResponse({ status: 200, description: '조회 성공' })
  getMe(@Request() req: TokenRequest) {
    const payload = req.user;
    console.log('payload', payload);
    return { payload };
  }

  @Post('sign-out')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: '로그아웃',
    description: '사용자의 Refresh Token을 파기하고 로그아웃 처리합니다.',
  })
  @ApiResponse({ status: 200, description: '로그아웃 성공' })
  async signOut(
    @Request() request: TokenRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { sub } = request.user;
    await this.authService.signOut(sub, res);
  }
}

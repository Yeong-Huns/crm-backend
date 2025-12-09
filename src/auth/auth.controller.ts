import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
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
import { ApiTags } from '@nestjs/swagger';

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
  registerUser(@Body() signUpDto: SignUpDto) {
    return this.authService.registerUser(signUpDto);
  }

  @Public()
  @Post('sign-in')
  async loginUser(
    @Res({ passthrough: true }) res: Response,
    @Body() signInDto: SignInDto,
  ) {
    return await this.authService.login(signInDto, res);
  }

  @Refresh()
  @Post('token/access')
  async rotateAccessToken(@Request() req: TokenRequest) {
    const { sub, role } = req.user;
    const accessToken = await this.authService.issueAccessToken({
      id: sub,
      role: role,
    });
    return { accessToken };
  }

  @Role(UserRole.SUPERVISOR)
  @Get('private')
  private(@Request() request: TokenRequest) {
    return request.user;
  }

  @Get('me')
  getMe(@Request() req: TokenRequest) {
    const payload = req.user;
    console.log('payload', payload);
    return { payload };
  }
}

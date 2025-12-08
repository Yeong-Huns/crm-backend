import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';

import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import { TokenPayload } from '../const/auth.const';

/* token/access 부분 엔드포인트에만 적용(엑세스 토큰 재발급) */
@Injectable()
export class RefreshGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const refreshToken = request.cookies?.refreshToken as string | undefined;
    if (!refreshToken)
      throw new UnauthorizedException('리프레쉬 토큰이 존재하지 않습니다.');

    try {
      const decodedPayLoad = this.jwtService.decode<TokenPayload>(refreshToken);
      if (!decodedPayLoad || typeof decodedPayLoad !== 'object')
        throw new UnauthorizedException('유효하지 않은 토큰입니다.');

      if (decodedPayLoad.type !== 'refresh')
        throw new UnauthorizedException('잘못된 토큰 타입입니다.');

      const payload = await this.jwtService.verifyAsync<TokenPayload>(
        refreshToken,
        {
          secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
        },
      );
      request.user = payload;
      return true;
    } catch (e) {
      const error = e as Error;
      const errorMessage =
        error.name === 'TokenExpiredError'
          ? '리프레시 토큰이 만료되었습니다'
          : '유효하지 않은 리프레시 토큰';
      throw new UnauthorizedException(errorMessage);
    }
  }
}

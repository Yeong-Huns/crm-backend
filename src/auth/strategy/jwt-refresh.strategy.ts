import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import { TokenPayload } from '../const/auth.const';
import { Injectable, UnauthorizedException } from '@nestjs/common';

interface ExtendedExpressRequest extends Request {
  cookies: { refreshToken?: string };
}

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: ExtendedExpressRequest) => {
          return request.cookies?.refreshToken;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('REFRESH_TOKEN_SECRET'),
      passReqToCallback: true /* validate 함수에서 req 객체를 쓰기 위해 true 설정 */,
    });
  }

  validate(req: ExtendedExpressRequest, payload: TokenPayload) {
    if (payload.type !== 'refresh')
      throw new UnauthorizedException('잘못된 토큰 타입입니다.');

    const refreshToken = req.cookies.refreshToken;
    return { ...payload, refreshToken };
  }
}

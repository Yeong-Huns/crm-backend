import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { TokenPayload } from '../const/auth.const';

export class JwtAuthGuard extends AuthGuard('jwt') {}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly configService: ConfigService) {
    super({
      /* Bearer $token 추출 */
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false /* 토큰 만료를 무시하고 검증할 것인가? */,
      secretOrKey: configService.get<string>('ACCESS_TOKEN_SECRET'),
    });
  }

  validate(payload: TokenPayload) {
    if (payload.type !== 'access')
      throw new UnauthorizedException('잘못된 토큰 타입입니다.');
    return payload;
  }
}

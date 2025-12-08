import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, TokenExpiredError } from '@nestjs/jwt';
import type { NextFunction, Request, Response } from 'express';
import { TokenPayload } from '../const/auth.const';

interface ExtendedRequest extends Request {
  cookies: { accessToken?: string };
}

@Injectable()
export class CookieParserMiddleware implements NestMiddleware {
  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async use(req: ExtendedRequest, res: Response, next: NextFunction) {
    /* 리프레시 토큰 요청 경로 체크 */
    /*if (req.path === '/auth/token/access') {
      return next();
    }*/
    try {
      const cookie = req.cookies.accessToken;
      console.log('cookie', cookie);
      if (!cookie) {
        next();
        return;
      }
      const decodedPayLoad = this.jwtService.decode<TokenPayload>(cookie);
      console.log('decodedCookie', decodedPayLoad);
      if (!decodedPayLoad || typeof decodedPayLoad !== 'object')
        throw new UnauthorizedException('유효하지 않은 토큰입니다.');

      if (decodedPayLoad.type !== 'access')
        throw new UnauthorizedException('잘못된 토큰 타입입니다.');

      req.user = await this.jwtService.verifyAsync(cookie, {
        secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
      });
      next();
    } catch (e) {
      if (e instanceof TokenExpiredError) {
        throw new UnauthorizedException('만료된 토큰입니다.');
      }
      next(e);
    }
  }
}

import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Reflector } from '@nestjs/core';
import { Public } from '../decorator/public.decorator';
import { RefreshAuth } from '../decorator/refresh-auth.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }
  canActivate(context: ExecutionContext) {
    /*@Public() 검사 패스 */
    const isPublic = this.reflector.getAllAndOverride<boolean>(Public, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    /* @Refresh() 데코레이터 확인 -> Guard(RefreshGuard) 연결 */
    const isRefresh = this.reflector.getAllAndOverride<boolean>(RefreshAuth, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isRefresh) {
      return true;
    }

    /* Access Token Guard */
    return super.canActivate(context);
  }
}

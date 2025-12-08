import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '../decorator/role-based-access-control.decorator';
import { UserRole as userRole } from '../../user/type/user.role';
import type { Request } from 'express';

interface extendedRole extends Request {
  user: { role: userRole };
}

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext) {
    const role = this.reflector.get<userRole>(Role, context.getHandler());
    /* Role Enum 에 등록되지 않은 역할이면 pass */
    if (!Object.values(userRole).includes(role)) return true;

    const request = context.switchToHttp().getRequest<extendedRole>();
    const user = request.user;
    if (!user) return false;

    const userRoleIndex = this.getEnumIndex(userRole, user.role);
    const requiredRoleIndex = this.getEnumIndex(userRole, role);
    return userRoleIndex <= requiredRoleIndex;
  }

  /* Role Enum 의 인덱스를 활용한 계층형 권한 Guard 구현 */
  private getEnumIndex(roleEnum: typeof userRole, value: string): number {
    const keys = Object.keys(roleEnum).filter((key) => isNaN(Number(key)));
    return keys.indexOf(value);
  }
}

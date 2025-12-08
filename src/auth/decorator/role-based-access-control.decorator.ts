import { Reflector } from '@nestjs/core';
import { UserRole as userRole } from '../../user/type/user.role';

export const Role = Reflector.createDecorator<userRole>();

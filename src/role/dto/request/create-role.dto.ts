import { IsEnum } from 'class-validator';
import { UserRole } from '../../../user/type/user.role';

export class CreateRoleDto {
  @IsEnum(UserRole)
  role: UserRole;
}

import { UserRole } from '../../user/type/user.role';

export const REFRESH_TOKEN = true;
export const ACCESS_TOKEN = false;

export type UserCredential = {
  id: number;
  role: UserRole;
};

export type TokenPayload = {
  sub: number;
  role: UserRole;
  type: 'access' | 'refresh';
  iat: number;
  exp: number;
};

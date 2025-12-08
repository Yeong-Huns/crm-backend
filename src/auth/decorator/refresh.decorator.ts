import { applyDecorators, UseGuards } from '@nestjs/common';
import { RefreshAuth } from './refresh-auth.decorator';
import { AuthGuard } from '@nestjs/passport';

export function Refresh() {
  return applyDecorators(
    RefreshAuth() /* 전역 가드 pass */,
    UseGuards(AuthGuard('jwt-refresh')) /* Refresh Strategy */,
  );
}

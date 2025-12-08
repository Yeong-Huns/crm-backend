/* public(Guard 적용 X) 하고싶은 엔드포인트 지정 */

import { Reflector } from '@nestjs/core';

export const Public = Reflector.createDecorator<boolean>();

import { Controller } from '@nestjs/common';
import { RegistrationStatusService } from './registration-status.service';

@Controller('registration-status')
export class RegistrationStatusController {
  constructor(
    private readonly registrationStatusService: RegistrationStatusService,
  ) {}
}

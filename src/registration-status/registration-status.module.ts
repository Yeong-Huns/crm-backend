import { Module } from '@nestjs/common';
import { RegistrationStatusService } from './registration-status.service';
import { RegistrationStatusController } from './registration-status.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RegistrationStatus } from './entities/registration-status.entity';

@Module({
  imports: [TypeOrmModule.forFeature([RegistrationStatus])],
  controllers: [RegistrationStatusController],
  providers: [RegistrationStatusService],
})
export class RegistrationStatusModule {}

import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { User } from '../../user/entities/user.entity';

@Entity({ name: 'registration_status' })
export class RegistrationStatus {
  @ApiProperty({ description: '가입 대기 상태 키' })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ description: '가입 대기 상태 명' })
  @Column()
  name: string;

  @OneToMany(() => User, (user) => user.registrationStatus)
  user: User;
}

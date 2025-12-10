import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  OneToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { Role } from '../../role/entities/role.entity';
import { RegistrationStatus } from '../../registration-status/entities/registration-status.entity';

@Entity({ name: 'users' })
export class User {
  @ApiProperty({ description: '관리자 Key' })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ description: '관리자 이메일' })
  @Column({ unique: true })
  email: string;

  @ApiProperty({ description: '관리자 패스워드' })
  @Column()
  password: string;

  @ApiProperty({ description: '관리자 이름' })
  @Column()
  name: string;

  @ApiProperty({ description: 'refreshToken', nullable: true })
  @Column({ name: 'refresh_token', nullable: true })
  refreshToken?: string;

  @ApiProperty({ description: '국가코드' })
  @Column({ name: 'country_id' })
  country: number;

  @ApiProperty({ description: '조직코드' })
  @Column({ name: 'organization_id' })
  organization: number;

  @ApiProperty({ description: '계정 생성일' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @ApiProperty({ description: '계정 수정일' })
  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @ApiProperty({ description: '주소' })
  @Column({ name: 'address' })
  address: string;

  @ApiProperty({ description: '권한' })
  @ManyToOne(() => Role, (role) => role.id, { nullable: false, cascade: true })
  @JoinColumn({ name: 'role_id' })
  role: Role;

  @ApiProperty({ description: '가입 상태' })
  @ManyToOne(
    () => RegistrationStatus,
    (registrationStatus) => registrationStatus.id,
    { nullable: false, cascade: true },
  )
  @JoinColumn({ name: 'registration_id' })
  registrationStatus: RegistrationStatus;
}

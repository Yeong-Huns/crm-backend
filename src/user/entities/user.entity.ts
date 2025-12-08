import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { UserRole } from '../type/user.role';
import { ApiProperty } from '@nestjs/swagger';

@Entity()
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

  @ApiProperty({ description: '권한' })
  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.ADMIN,
  })
  role: UserRole;

  @ApiProperty({ description: '계정 생성일' })
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty({ description: 'refreshToken', nullable: true })
  @Column({ nullable: true })
  refreshToken?: string;
}

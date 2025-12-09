import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { Role } from '../../role/entities/role.entity';

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
  @OneToOne(() => Role, (role) => role.id)
  @JoinColumn()
  role: Role;

  @ApiProperty({ description: '계정 생성일' })
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty({ description: 'refreshToken', nullable: true })
  @Column({ nullable: true })
  refreshToken?: string;
}

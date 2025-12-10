import {
  Column,
  Entity,
  OneToMany,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from '../../user/type/user.role';
import { User } from '../../user/entities/user.entity';

@Entity({ name: 'role' })
export class Role {
  @ApiProperty({ description: 'Role Key' })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ description: '권한' })
  @Column({
    type: 'enum',
    enum: UserRole,
    unique: true,
  })
  name: UserRole;

  @OneToMany(() => User, (user) => user.role)
  user: User;
}

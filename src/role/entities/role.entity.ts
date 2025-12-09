import { Column, Entity, OneToOne, PrimaryGeneratedColumn } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from '../../user/type/user.role';
import { User } from '../../user/entities/user.entity';

@Entity()
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
  role: UserRole;

  @OneToOne(() => User, (user) => user.role)
  user: User;
}

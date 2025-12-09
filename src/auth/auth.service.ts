import { BadRequestException, Injectable } from '@nestjs/common';
import { Response } from 'express';
import { User } from '../user/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ENV_VARIABLES } from '../common/const/env.variables';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { UserRole } from '../user/type/user.role';
import { Role } from '../role/entities/role.entity';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async registerUser(signUpDto: SignUpDto) {
    return await this.userRepository.manager.transaction(
      'READ COMMITTED',
      async (manager) => {
        const { email, password, name, role: roleId } = signUpDto;
        const isExist = await manager.getRepository(User).existsBy({ email });
        if (isExist)
          throw new BadRequestException(
            '해당 이메일로 가입된 계정이 존재합니다.',
          );

        /* 비밀번호 암호화! */
        const hash = await bcrypt.hash(
          password,
          this.configService.get<number>(ENV_VARIABLES.hashRounds),
        );

        const role = await manager
          .getRepository(Role)
          .findOneBy({ id: roleId });

        /* DB 저장 */
        return await manager.getRepository(User).save({
          email,
          password: hash,
          name,
          role,
        });
      },
    );
  }

  async login(signInDto: SignInDto, res: Response) {
    const { email, password } = signInDto;

    /* validation*/
    const user = await this.authenticate(email, password);

    await this.issueRefreshToken(user, res);

    const accessToken = await this.issueAccessToken({
      id: user.id,
      role: user.role.role,
    });

    return { accessToken };
  }

  async authenticate(email: string, password: string) {
    const user = await this.userRepository
      .createQueryBuilder('user')
      .innerJoinAndSelect('user.role', 'role')
      .getOne();

    console.log('user', user);
    if (!user) throw new BadRequestException('잘못된 로그인 정보입니다.');

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword)
      throw new BadRequestException('잘못된 비밀번호 입니다.');

    return user;
  }

  async signOut(id: number, res: Response) {
    await this.userRepository.update(id, { refreshToken: null });
    res.clearCookie('refreshToken');
  }

  private async issueRefreshToken(user: User, res: Response) {
    const token = await this.jwtService.signAsync(
      { sub: user.id, role: user.role.role, type: 'refresh' },
      {
        secret: this.configService.get('REFRESH_TOKEN_SECRET'),
        expiresIn: '24h',
      },
    );

    await this.userRepository.update(user.id, { refreshToken: token });

    res.cookie('refreshToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000,
    });
  }

  async issueAccessToken({ id, role }: { id: number; role: UserRole }) {
    return this.jwtService.signAsync(
      { sub: id, role, type: 'access' },
      {
        secret: this.configService.get('ACCESS_TOKEN_SECRET'),
        expiresIn: '15m',
      },
    );
  }
}

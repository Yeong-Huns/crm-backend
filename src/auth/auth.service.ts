import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Response } from 'express';
import { User } from '../user/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService, TokenExpiredError } from '@nestjs/jwt';
import { ENV_VARIABLES } from '../common/const/env.variables';
import { TokenPayload, UserCredential } from './const/auth.const';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { UserRole } from '../user/type/user.role';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  parseBasicToken(rawToken: string) {
    const tokenSplit = rawToken.split(' ');
    if (tokenSplit.length !== 2)
      throw new BadRequestException('올바르지않은 토큰 포맷');

    /* 추출한 토큰을 base64 디코딩으로 이메일, 비밀번호 나눔 */
    const [basic, token] = tokenSplit;
    if (basic.toLowerCase() !== 'basic')
      throw new BadRequestException('올바르지않은 토큰 포맷');

    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    const decodedTokenSplit = decoded.split(':');
    if (decodedTokenSplit.length !== 2)
      throw new BadRequestException('올바르지않은 토큰 포맷');

    /* 이메일, 패스워드 추출 */
    const [email, password] = decodedTokenSplit;

    return { email, password };
  }

  async parseBearerToken(authHeader: string, isRefreshToken: boolean) {
    /* 헤더 형식 검증 */
    const tokenSplit = authHeader.split(' ');
    if (tokenSplit.length !== 2 || tokenSplit[0].toLowerCase() !== 'bearer') {
      throw new BadRequestException('Bearer 토큰 형식이 올바르지 않습니다');
    }

    /* SECRET 선택 */
    const secret = isRefreshToken
      ? this.configService.get<string>(ENV_VARIABLES.refreshTokenSecret)
      : this.configService.get<string>(ENV_VARIABLES.accessTokenSecret);

    try {
      /* 토큰 검증 */
      const token = tokenSplit[1];
      const payload = await this.jwtService.verifyAsync<TokenPayload>(token, {
        secret,
      });

      /* 토큰 타입 검증 */
      const expectedType = isRefreshToken ? 'refresh' : 'access';
      if (payload.type !== expectedType) {
        throw new BadRequestException(`${expectedType} 토큰이 필요합니다`);
      }

      return payload;
    } catch (e) {
      if (e instanceof BadRequestException) throw e;
      if (e instanceof TokenExpiredError) {
        throw new UnauthorizedException('만료된 토큰');
      }
      throw new UnauthorizedException('유효하지 않은 토큰');
    }
  }

  async registerUser(signUpDto: SignUpDto) {
    /* rawToken -> Basic $token */
    const { email, password, name } = signUpDto;
    const isExist = await this.userRepository.existsBy({ email });
    if (isExist)
      throw new BadRequestException('해당 이메일로 가입된 계정이 존재합니다.');

    /* 비밀번호 암호화! */
    const hash = await bcrypt.hash(
      password,
      this.configService.get<number>(ENV_VARIABLES.hashRounds),
    );

    /* DB 저장 */
    await this.userRepository.save({
      email,
      password: hash,
      name,
    });

    /* 생성 유저 반환 */
    return await this.userRepository.findOneBy({ email });
  }

  async authenticate(email: string, password: string) {
    const user = await this.userRepository.findOneBy({ email });
    if (!user) throw new BadRequestException('잘못된 로그인 정보입니다.');

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword)
      throw new BadRequestException('잘못된 비밀번호 입니다.');

    return user;
  }

  async issueToken(
    user: UserCredential,
    isRefreshToken: boolean,
    res: Response,
  ) {
    const accessTokenSecret = this.configService.get<string>(
      ENV_VARIABLES.accessTokenSecret,
    );
    const refreshTokenSecret = this.configService.get<string>(
      ENV_VARIABLES.refreshTokenSecret,
    );
    const type = isRefreshToken ? 'refresh' : 'access';
    const token = await this.jwtService.signAsync(
      {
        sub: user.id,
        role: user.role,
        type: type,
      },
      {
        secret: isRefreshToken ? refreshTokenSecret : accessTokenSecret,
        expiresIn: isRefreshToken ? '24h' : 300,
      },
    );
    res.cookie(type + 'Token', token, {
      httpOnly: true,
      sameSite: 'none',
      secure: false,
      maxAge: isRefreshToken ? 24 * 60 * 60 * 1000 : 300 * 1000,
      /*expires: isRefreshToken
        ? new Date(Date.now() + 24 * 60 * 60 * 1000)
        : new Date(Date.now() + 300 * 1000),*/
      path: isRefreshToken ? '/auth/token/access' : '/',
    });
  }

  async login(signInDto: SignInDto, res: Response) {
    const { email, password } = signInDto;

    /* validation*/
    const user = await this.authenticate(email, password);

    await this.issueRefreshToken(user, res);

    const accessToken = await this.issueAccessToken({
      id: user.id,
      role: user.role,
    });

    return { accessToken };
  }

  private async issueRefreshToken(user: User, res: Response) {
    const token = await this.jwtService.signAsync(
      { sub: user.id, role: user.role, type: 'refresh' },
      {
        secret: this.configService.get('REFRESH_TOKEN_SECRET'),
        expiresIn: '24h',
      },
    );

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

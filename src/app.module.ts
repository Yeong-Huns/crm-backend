import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import Joi from 'joi';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { addTransactionalDataSource } from 'typeorm-transactional';
import { ENV_VARIABLES } from './common/const/env.variables';
import { User } from './user/entities/user.entity';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { JwtAuthGuard } from './auth/guard/access-token.guard';
import { RoleGuard } from './auth/guard/role.guard';
import { RoleModule } from './role/role.module';
import { Role } from './role/entities/role.entity';
import { RegistrationStatusModule } from './registration-status/registration-status.module';
import { RegistrationStatus } from './registration-status/entities/registration-status.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        ENV: Joi.string().valid('dev', 'prod').required(),
        DB_TYPE: Joi.string().valid('mariadb').required(),
        DB_HOST: Joi.string().required(),
        DB_PORT: Joi.number().required(),
        DB_USERNAME: Joi.string().required(),
        DB_PASSWORD: Joi.string().required(),
        DB_DATABASE: Joi.string().required(),
        HASH_ROUNDS: Joi.number().required(),
        ACCESS_TOKEN_SECRET: Joi.string().required(),
        REFRESH_TOKEN_SECRET: Joi.string().required(),
      }),
    }),
    TypeOrmModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        type: configService.get<string>(ENV_VARIABLES.dbType) as 'mariadb',
        host: configService.get<string>(ENV_VARIABLES.dbHost),
        port: configService.get<number>(ENV_VARIABLES.dbPort),
        username: configService.get<string>(ENV_VARIABLES.dbUsername),
        password: configService.get<string>(ENV_VARIABLES.dbPassword),
        database: configService.get<string>(ENV_VARIABLES.dbDatabase),
        entities: [User, Role, RegistrationStatus],
        synchronize: true,
        logging: true,
        logger: 'formatted-console',
      }),
      inject: [ConfigService],
      /* 트랜잭션 추가 */
      dataSourceFactory: async (options) => {
        if (!options) throw new Error('Invalid options passed');

        const dataSource = new DataSource(options);
        return addTransactionalDataSource(await dataSource.initialize());
      },
    }),
    AuthModule,
    UserModule,
    RoleModule,
    RegistrationStatusModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: 'APP_GUARD',
      useClass: JwtAuthGuard,
    },
    {
      provide: 'APP_GUARD',
      useClass: RoleGuard,
    },
    AppService,
  ],
})
export class AppModule {}

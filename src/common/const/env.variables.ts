export const ENV_VARIABLES = {
  env: 'ENV',
  dbType: 'DB_TYPE',
  dbHost: 'DB_HOST',
  dbPort: 'DB_PORT',
  dbUsername: 'DB_USERNAME',
  dbPassword: 'DB_PASSWORD',
  dbDatabase: 'DB_DATABASE',
  hashRounds: 'HASH_ROUNDS',
  accessTokenSecret: 'ACCESS_TOKEN_SECRET',
  refreshTokenSecret: 'REFRESH_TOKEN_SECRET',
  accessTokenExpiresIn: 'ACCESS_TOKEN_EXPIRES_IN',
  refreshTokenExpiresIn: 'REFRESH_TOKEN_EXPIRES_IN',
};

export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
}

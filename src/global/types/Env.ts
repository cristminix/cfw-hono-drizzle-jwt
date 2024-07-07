export type Env = {
  DB: D1Database
  MY_VAR: string
  PRIVATE: string
  SECRET: string
  ALLOWED_ORIGINS: any
  JWT_FINGERPRINT_COOKIE_NAME: string
  JWT_FINGERPRINT_REFRESH_COOKIE_NAME: string

  REFRESH_TOKEN_EXPIRATION: number
  TOKEN_EXPIRATION: number
  IDB_KEYVAL: KVNamespace
}

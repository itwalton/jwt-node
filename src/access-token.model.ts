export type AccessTokenPayload = {
  jti: string
  iss: string
  aud: string[]
  sub: string
  exp: number
  nbf: Date
  iat: Date
}

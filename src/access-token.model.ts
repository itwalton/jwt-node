export type AccessTokenPayload = {
  iss: string
  aud: string[]
  sub: string
  exp: number
  nbf: Date
  iat: Date
}

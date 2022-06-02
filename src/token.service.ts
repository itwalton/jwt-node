import base64url from 'base64url'
import { add, isAfter } from 'date-fns'
import crypto, { type KeyObject } from 'crypto'
import { v4 as uuidv4 } from 'uuid'

import { AccessTokenPayload } from './access-token.model'

export const DELIMITER = '.'

export type IssueAccessTokenOptions = {
  customClaims?: Record<string, unknown>
  expiresOn?: Date
}

export class TokenService {
  private readonly publicKey: KeyObject
  private readonly privateKey: KeyObject

  constructor(
    private readonly issuer: string,
    private readonly audience: string[],
    private readonly algorithm: 'SHA256',
    publicKeyPEMBuffer: Buffer,
    privateKeyPEMBuffer: Buffer
  ) {
    this.publicKey = crypto.createPublicKey(publicKeyPEMBuffer)
    this.privateKey = crypto.createPrivateKey(privateKeyPEMBuffer)
  }

  async issueAccessToken(
    subject: string,
    options: IssueAccessTokenOptions = {}
  ): Promise<{ expiresOn: Date; accessToken: string }> {
    const { customClaims = {}, expiresOn = add(new Date(), { minutes: 15 }) } =
      options

    const now = new Date()

    const header = JSON.stringify({
      typ: 'JWT',
      alg: 'RS256',
    })

    const payload: AccessTokenPayload = {
      ...customClaims,

      jti: uuidv4(),
      iss: this.issuer,
      aud: this.audience,
      sub: subject,
      exp: expiresOn.getTime(),
      nbf: now, // notBefore
      iat: now, // issuedAt
    }

    const stringifiedPayload = JSON.stringify(payload)
    const signature = crypto.sign(
      this.algorithm,
      Buffer.from(stringifiedPayload),
      {
        key: this.privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      }
    )

    return {
      expiresOn,
      accessToken: [header, stringifiedPayload, signature]
        .map((part) => base64url.encode(part))
        .join(DELIMITER),
    }
  }

  async validateAccessToken(accessToken: string): Promise<boolean> {
    const [, payloadBuffer, signatureBuffer] = accessToken
      .split(DELIMITER)
      .map(base64url.toBuffer)

    const { exp } = JSON.parse(payloadBuffer.toString()) as { exp: number }
    const isTokenWithinExpirationWindow = isAfter(exp, new Date())

    return (
      isTokenWithinExpirationWindow &&
      crypto.verify(
        this.algorithm,
        payloadBuffer,
        {
          key: this.publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        },
        signatureBuffer
      )
    )
  }

  extractPayload(accessToken: string): AccessTokenPayload {
    const tokenParts = accessToken.split(DELIMITER)

    const isValidTokenStructure = tokenParts.length === 3
    if (!isValidTokenStructure) {
      throw new Error('Invalid token structure')
    }

    const stringifiedPayload = tokenParts[1]
    const { nbf, iat, ...rest } = JSON.parse(
      base64url.toBuffer(stringifiedPayload).toString()
    )

    return {
      ...rest,
      nbf: new Date(nbf),
      iat: new Date(iat),
    }
  }

  extractSubject(accessToken: string): string {
    const { sub } = this.extractPayload(accessToken)
    return sub
  }
}

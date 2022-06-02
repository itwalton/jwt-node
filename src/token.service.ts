import base64url from 'base64url'
import { add, isAfter } from 'date-fns'
import crypto, { type KeyObject } from 'crypto'

import { AccessTokenPayload } from './access-token.model'

export const DELIMITER = '.'

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
    expiresOn: Date = add(new Date(), {
      minutes: 15,
    })
  ): Promise<{ expiresOn: Date; accessToken: string }> {
    const now = new Date()

    const header = JSON.stringify({
      typ: 'JWT',
      alg: 'RS256',
    })

    const payload = JSON.stringify({
      iss: this.issuer,
      aud: this.audience,
      sub: subject,
      exp: expiresOn.getTime(),
      nbf: now, // notBefore
      iat: now, // issuedAt
    })

    const signature = crypto.sign(this.algorithm, Buffer.from(payload), {
      key: this.privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    })

    return {
      expiresOn,
      accessToken: [header, payload, signature]
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

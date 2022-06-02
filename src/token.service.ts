import crypto from 'crypto'
import base64url from 'base64url'
import { add, isAfter } from 'date-fns'
import type { KeyObject } from 'crypto'
import { isEqual, pipe, split, join, map, size } from 'lodash/fp'

const DELIMITER = '.'

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
      accessToken: pipe(
        map(base64url.encode),
        join(DELIMITER)
      )([header, payload, signature]),
    }
  }

  async validateAccessToken(accessToken: string): Promise<boolean> {
    const [, payloadBuffer, signatureBuffer] = pipe(
      split(DELIMITER),
      map(base64url.toBuffer)
    )(accessToken)

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

  getSubjectFromAccessToken(accessToken: string): string {
    const tokenParts = split(DELIMITER, accessToken)

    const isValidTokenStructure = pipe(size, isEqual(3))(tokenParts)
    if (!isValidTokenStructure) {
      throw new Error('Invalid token structure')
    }

    const payload = tokenParts[1]
    const { sub } = JSON.parse(base64url.toBuffer(payload).toString())

    return sub
  }
}

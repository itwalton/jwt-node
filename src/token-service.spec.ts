import crypto from 'crypto'
import base64url from 'base64url'
import {
  add,
  isAfter,
  isBefore,
  sub,
} from 'date-fns'

import { DELIMITER, TokenService } from './token.service'
import { AccessTokenPayload } from 'access-token.model'

const isDateEqual = (date: Date, targetDate: Date): boolean => isBefore(date, add(targetDate, { seconds: 1 })) && isAfter(date, sub(targetDate, { seconds: 1 }))

describe('TokenService', () => {
  let publicKey: Buffer
  let privateKey: Buffer

  beforeAll(async () => {
    const keyPair = await crypto.generateKeyPairSync('rsa', { modulusLength: 512 })
    publicKey = Buffer.from(keyPair.publicKey.export({ type: 'pkcs1', format: 'pem' }))
    privateKey = Buffer.from(keyPair.privateKey.export({ type: 'pkcs1', format: 'pem' }))
  })

  describe('.issueAccessToken', () => {
    it('has three period-delimited strings', async () => {
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)

      const { accessToken } = await tokenService.issueAccessToken('foo subj')

      const accessTokenParts = accessToken.split(DELIMITER)
      expect(accessTokenParts).toHaveLength(3)
      expect(accessTokenParts.every((part) => typeof part === 'string')).toBe(true)
    })

    it('has a header', async () => {
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)

      const { accessToken } = await tokenService.issueAccessToken('foo subj')

      const header = JSON.parse(base64url.decode(accessToken.split(DELIMITER)[0]))
      expect(header).toEqual({
        typ: 'JWT',
        alg: 'RS256',
      })
    })

    it('has a payload', async () => {
      const now = new Date()
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)
      const { accessToken } = await tokenService.issueAccessToken('foo subj')

      const payload = JSON.parse(base64url.decode(accessToken.split(DELIMITER)[1])) as AccessTokenPayload
      
      expect(Object.keys(payload)).toStrictEqual(['jti', 'iss', 'aud', 'sub', 'exp', 'nbf', 'iat'])
      expect(payload.iss).toBe('foo issuer')
      expect(payload.aud).toEqual(['example.com'])
      expect(payload.sub).toBe('foo subj')
      expect(isDateEqual(new Date(payload.exp), add(now, { minutes: 15 }))).toBe(true)
      expect(isDateEqual(new Date(payload.nbf), now)).toBe(true)
      expect(isDateEqual(new Date(payload.iat), now)).toBe(true)
    })

    it('has a payload with custom expiration', async () => {
      const customExpiresOn = add(new Date(), { days: 1 })
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)

      const { accessToken, expiresOn } = await tokenService.issueAccessToken('foo subj', customExpiresOn)

      const payload = JSON.parse(base64url.decode(accessToken.split(DELIMITER)[1]))
      expect(customExpiresOn).toBe(expiresOn)
      expect(payload.exp).toBe(customExpiresOn.getTime())
    })

    it('has a signature', async () => {
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)

      const { accessToken } = await tokenService.issueAccessToken('foo subj')

      const [, payload, signature] = accessToken.split(DELIMITER).map(base64url.toBuffer)
      expect(
        crypto.verify(
          'SHA256',
          payload,
          { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
          signature,
        ),
      ).toBe(true)
    })
  })

  describe('.validateAccessToken', () => {
    it('is false if past exp', async () => {
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)
      const { accessToken } = await tokenService.issueAccessToken('foo subj', sub(new Date(), { minutes: 1 }))

      expect(await tokenService.validateAccessToken(accessToken)).toBe(false)
    })

    it('is false if bad signature', async () => {
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)
      const { accessToken } = await tokenService.issueAccessToken('foo subj')

      const badAccessToken = accessToken + 'a'

      expect(await tokenService.validateAccessToken(badAccessToken)).toBe(false)
    })

    it('is true with valid signature', async () => {
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)
      const { accessToken } = await tokenService.issueAccessToken('foo subj')

      expect(await tokenService.validateAccessToken(accessToken)).toBe(true)
    })
  })

  describe('.extractPayload', () => {
    it('ensures token has three period-delimited parts', async () => {
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)

      const malformedAccessToken = 'aaa.bbb'

      expect(() => tokenService.extractPayload(malformedAccessToken)).toThrowError('Invalid token structure')
    })

    it('returns payload', async () => {
      const now = new Date()
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)
      const { accessToken } = await tokenService.issueAccessToken('foo subj')

      const payload = tokenService.extractPayload(accessToken)

      expect(Object.keys(payload)).toStrictEqual(['jti', 'iss', 'aud', 'sub', 'exp', 'nbf', 'iat'])
      expect(payload.iss).toBe('foo issuer')
      expect(payload.aud).toEqual(['example.com'])
      expect(payload.sub).toBe('foo subj')
      expect(isDateEqual(new Date(payload.exp), add(now, { minutes: 15 }))).toBe(true)
      expect(isDateEqual(new Date(payload.nbf), now)).toBe(true)
      expect(isDateEqual(new Date(payload.iat), now)).toBe(true)
    })
  })

  describe('.extractSubject', () => {
    it('ensures token has three period-delimited parts', async () => {
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)

      const malformedAccessToken = 'aaa.bbb'

      expect(() => tokenService.extractSubject(malformedAccessToken)).toThrowError('Invalid token structure')
    })

    it('returns subject', async () => {
      const tokenService = new TokenService('foo issuer', ['example.com'], 'SHA256', publicKey, privateKey)

      const { accessToken } = await tokenService.issueAccessToken('foo subj')

      expect(tokenService.extractSubject(accessToken)).toBe('foo subj')
    })
  })
})

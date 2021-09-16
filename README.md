# JWT Node

## Introduction

  Issues and verifies JWT access tokens from a supplied keypair

  See (RFC7519)[https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3]

## Usage

  1. Read PEM-formatted keys into memory (see fs)
  2. Instantiate token service with:

    * `issuer`: the CN of the service issuing the token
    * `subject`: the CN of any service that may accept the token
    * `algorithm`: only supports 'SHA256' for now
    * `publicKeyPEMBuffer`: A Buffer representation of a PEM encoded public key
    * `privateKeyPEMBuffer`: A Buffer representation of a PEM encoded private key

### Example

  ```
  // instantiate the token service
  const tokenService = new TokenService(
    process.env.TOKEN_ISSUER as string,
    [process.env.TOKEN_AUDIENCE as string],
    'SHA256',
    publicKeyPEMBuffer,
    privateKeyPEMBuffer,
  )

  ```

  ```

  // after a successful login
  const {expiresOn, accessToken} = await tokenService.issueAccessToken(user.id)

  ```

  ```

  // on a request to a protected route
  const isValid = await tokenService.validateAccessToken(accessToken)

  ```

### Getting Started

  1. Clone the repo
  2. Install dependencies `npm i`
  3. Run tests `npm test`
  4. Watch/compile `npm run start:dev`

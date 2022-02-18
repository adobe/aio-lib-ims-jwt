/*
Copyright 2020 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.
*/

const { parseJson, createJwt, verifyJwt } = require('../src/helpers')
const jwt = require('jsonwebtoken')
const mockExponentialBackoff = jest.fn()
jest.mock('@adobe/aio-lib-core-networking', () => ({
  HttpExponentialBackoff: jest.fn().mockImplementationOnce(() => ({
    exponentialBackoff: mockExponentialBackoff
  }))
}))
jest.mock('jsonwebtoken', () => ({
  decode: jest.fn(),
  verify: jest.fn(),
  sign: jest.fn()
}))

const gIms = {
  exchangeJwtToken: jest.fn(),
  getApiUrl: jest.fn()
}

jest.mock('fs', () => ({
  readFile: jest.fn(),
  readFileSync: jest.fn(),
  writeFileSync: jest.fn(),
  existsSync: jest.fn()
}))
const fs = require('fs')

beforeEach(() => {
  jest.restoreAllMocks()
  fs.readFile.mockReset()
  fs.existsSync.mockReset()
  fs.readFileSync.mockReset()
  fs.writeFileSync.mockReset()
  jwt.verify.mockReset()
  jwt.decode.mockReset()
  jwt.sign.mockReset()
  mockExponentialBackoff.mockReset()
})

test('parseJson', () => {
  const myString = 'some-string'
  const myArray = ['foo', 'bar']
  const myObject = { foo: 'bar' }

  expect(parseJson(myString)).toEqual(myString) // string, returns string
  expect(parseJson(JSON.stringify(myArray))).toEqual(myArray) // string contains array, returns json
  expect(parseJson(JSON.stringify(myObject))).toEqual(myObject) // string contains object, returns json
  expect(parseJson(myObject)).toEqual(myObject) // object, returns object
})

test('createJwt', async () => {
  const myJwtToken = 'my-jwt'
  const myAccessToken = 'my-access-token'

  const myConfig = {
    client_id: 'my-client-id',
    client_secret: 'my-client-secret',
    ims_org_id: 'my-ims-org-id',
    techacct: 'my-tech-acct',
    meta_scopes: ['my', 'meta', 'scopes'],
    private_key: ['-----BEGIN PRIVATE KEY-----', 'my', 'private', 'key']
  }

  const myPassphrase = 'my-passphrase'
  const privateKeyStringNewlines = '-----BEGIN PRIVATE KEY-----\nmy\nprivate\nkey'
  const privateKeyFile = '/my/private.key'
  const privateKeyStringifiedJson = '["-----BEGIN PRIVATE KEY-----", "my", "private", "key"]'
  const metaScopesStringifiedJson = '["my", "meta", "scopes"]'

  jwt.sign.mockImplementation(() => {
    return myJwtToken
  })

  gIms.exchangeJwtToken.mockImplementation((clientId, clientSecret, jwtToken) => {
    expect(jwtToken).toEqual(myJwtToken)
    return myAccessToken
  })

  let jwtObject

  // standard config
  jwtObject = createJwt(gIms, myConfig.clientId, myConfig.imsOrg, myConfig.techacct, myConfig.meta_scopes, myConfig.private_key)
  await expect(jwtObject).resolves.toEqual(myJwtToken)

  // standard config with passphrase (for coverage)
  jwtObject = createJwt(gIms, myConfig.clientId, myConfig.imsOrg, myConfig.techacct, myConfig.meta_scopes, myConfig.private_key, myPassphrase)
  await expect(jwtObject).resolves.toEqual(myJwtToken)

  // config with private_key as string (embedded newlines)
  jwtObject = createJwt(gIms, myConfig.clientId, myConfig.imsOrg, myConfig.techacct, myConfig.meta_scopes, privateKeyStringNewlines)
  await expect(jwtObject).resolves.toEqual(myJwtToken)

  // config with private_key as string (stringified json array), meta_scopes as string (stringified json array)
  jwtObject = createJwt(gIms, myConfig.clientId, myConfig.imsOrg, myConfig.techacct, metaScopesStringifiedJson, privateKeyStringifiedJson)
  await expect(jwtObject).resolves.toEqual(myJwtToken)

  // config with private_key as file
  fs.readFile.mockImplementation((a, cb) => cb(null, Buffer.from(privateKeyStringNewlines)))
  jwtObject = createJwt(gIms, myConfig.clientId, myConfig.imsOrg, myConfig.techacct, myConfig.meta_scopes, privateKeyFile)
  await expect(jwtObject).resolves.toEqual(myJwtToken)
  expect(fs.readFile).toHaveBeenCalledWith('/my/private.key', expect.any(Function))

  // config with private_key as file but invalid content
  fs.readFile.mockReset()
  fs.readFile.mockImplementation((a, cb) => cb(null, Buffer.from('-----NOT PRIVATE KEY-----\nmy private key')))
  jwtObject = createJwt(gIms, myConfig.clientId, myConfig.imsOrg, myConfig.techacct, myConfig.meta_scopes, privateKeyFile)
  await expect(jwtObject).rejects.toThrow('[IMSJWTSDK:INVALID_KEY_FILE] content of file \'/my/private.key\' is not a valid private key')

  // config with private_key as file and error reading it
  fs.readFile.mockReset()
  fs.readFile.mockImplementation((a, cb) => cb(new Error('fake')))
  jwtObject = createJwt(gIms, myConfig.clientId, myConfig.imsOrg, myConfig.techacct, myConfig.meta_scopes, privateKeyFile)
  await expect(jwtObject).rejects.toThrow('fake')

  // mock jwt.sign throwing an error
  jwt.sign.mockImplementation(() => {
    throw new Error('sign error')
  })
  jwtObject = createJwt(gIms, myConfig.clientId, myConfig.imsOrg, myConfig.techacct, myConfig.meta_scopes, myConfig.private_key, myConfig.passphrase)
  await expect(jwtObject).rejects.toThrow('[IMSJWTSDK:INVALID_KEY] Cannot sign the JWT, the private key or the passphrase is invalid')
})

describe('verifyJwt', () => {
  test('verifyJwt, cached cert, jwt.verify called', async () => {
    const privateKey = '-----BEGIN PRIVATE KEY-----'
    const myAccessToken = 'my-access-token'
    jwt.verify.mockImplementation(() => true)
    jwt.decode.mockImplementation(() => ({
      header: { x5u: 'myCertName' },
      payload: { type: 'access_token', state: '{"env": "prod"}' }
    }))
    fs.readFileSync.mockImplementation(() => privateKey)
    fs.existsSync.mockImplementation(() => true)
    await verifyJwt(myAccessToken)
    expect(jwt.verify).toHaveBeenCalledWith(myAccessToken, privateKey, { algorithms: ['RS256'] })
    expect(verifyJwt).not.toThrow()
  })
  test('verifyJwt, get cert, valid cert,', async () => {
    const privateKey = '-----BEGIN PRIVATE KEY-----'
    const myAccessToken = 'my-access-token'
    const decodedToken = {
      header: { x5u: 'myCertName' },
      payload: { type: 'access_token', state: '{"env": "prod"}' }
    }
    jwt.decode = jest.fn().mockImplementation(() => decodedToken)
    jwt.verify = jest.fn().mockImplementation(() => true)
    fs.writeFileSync.mockImplementation(() => true)
    fs.existsSync.mockImplementation(() => false)
    const res = {
      text: () => Promise.resolve(privateKey)
    }
    mockExponentialBackoff.mockResolvedValueOnce(res)

    await expect(verifyJwt(myAccessToken)).resolves.not.toThrow()
    expect(fs.writeFileSync).toHaveBeenCalledWith(expect.any(String), privateKey)
    expect(jwt.verify).toHaveBeenCalledWith(myAccessToken, privateKey, { algorithms: ['RS256'] })
  })
  test('verifyJwt, get cert, invalid cert,', async () => {
    const myAccessToken = 'my-access-token'
    jwt.decode.mockImplementation(() => ({
      header: { x5u: 'myCertName' },
      payload: { type: 'access_token', state: '{"env": "prod"}' }
    }))
    jwt.verify.mockImplementation(() => true)
    fs.existsSync.mockImplementation(() => false)
    const res = {
      text: () => Promise.resolve('invalid cert res')
    }
    mockExponentialBackoff.mockResolvedValueOnce(res)
    await expect(verifyJwt(myAccessToken)).rejects.toThrow()
    expect(fs.writeFileSync).not.toHaveBeenCalled()
    expect(jwt.verify).not.toHaveBeenCalledWith(myAccessToken, 'invalid cert res', { algorithms: ['RS256'] })
  })
  test('verifyJwt, _readOrGetCert invalid params, reject,', async () => {
    jwt.decode.mockImplementation(() => ({
      header: { x5u: '' },
      payload: { type: 'access_token', state: '{"env": ""}' }
    }))
    jwt.verify.mockImplementation(() => true)
    fs.existsSync.mockImplementation(() => false)
    await expect(verifyJwt('token')).rejects.toThrow()
    expect(mockExponentialBackoff).not.toHaveBeenCalled()
    expect(jwt.verify).not.toHaveBeenCalled()
  })
  test('verifyJwt, not access token, skip verify,', async () => {
    jwt.decode.mockImplementation(() => ({
      header: { x5u: '' },
      payload: { type: 'not_access', state: '{"env": ""}' }
    }))
    jwt.verify.mockImplementation(() => true)
    await expect(verifyJwt('token')).resolves.not.toThrow()
    expect(jwt.verify).not.toHaveBeenCalled()
  })
})

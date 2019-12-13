/*
Copyright 2018 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.
*/

const plugin = require('../src/ims-jwt')
const jwt = require('jsonwebtoken')

jest.mock('jsonwebtoken')

const gIms = {
  exchangeJwtToken: jest.fn(),
  getApiUrl: jest.fn()
}

const gConfig = {
  client_id: 'my-client-id',
  client_secret: 'my-client-secret',
  ims_org_id: 'my-ims-org-id',
  techacct: 'my-tech-acct',
  meta_scopes: 'my,meta,scopes',
  private_key: 'my-private-key'
}

beforeEach(() => {
  jest.restoreAllMocks()
})

test('has ims plugin interface', () => {
  expect(typeof plugin.supports).toEqual('function')
  expect(typeof plugin.imsLogin).toEqual('function')
})

test('supports() interface', () => {
  expect(plugin.supports(gConfig)).toBeTruthy()
  expect(plugin.supports({})).toBeFalsy()
  expect(plugin.supports()).toBeFalsy()
})

test('imsLogin() interface', async () => {
  const myJwtToken = 'my-jwt'
  const myAccessToken = 'my-access-token'

  const myPrivateKey = 'my-private-key'
  const myPrivateKeyPassphrase = 'my-private-key-passphrase'

  jwt.sign.mockImplementation(() => {
    return myJwtToken
  })

  gIms.exchangeJwtToken.mockImplementation((clientId, clientSecret, jwtToken) => {
    expect(jwtToken).toEqual(myJwtToken)
    return 'my-access-token'
  })

  // normal acceptable config
  await expect(plugin.imsLogin(gIms, gConfig)).resolves.toEqual(myAccessToken)

  // normal acceptable config, with passphrase for private key
  const configWithPrivateKeyPassphrase = Object.assign(gConfig, { passphrase: myPrivateKeyPassphrase })
  await expect(plugin.imsLogin(gIms, configWithPrivateKeyPassphrase)).resolves.toEqual(myAccessToken)

  // private key as a string array, not a string
  const configWithPrivateKeyArray = Object.assign(gConfig, { private_key: [myPrivateKey] })
  await expect(plugin.imsLogin(gIms, configWithPrivateKeyArray)).resolves.toEqual(myAccessToken)

  // config missing a property
  const configMissingProperties = Object.assign({}, gConfig)
  delete configMissingProperties.client_id
  await expect(plugin.imsLogin(gIms, configMissingProperties)).rejects.toEqual(new Error('JWT not supported due to some missing properties: client_id'))

  // mock jwt.sign throwing an error
  jwt.sign.mockImplementation(() => {
    throw new Error('sign error')
  })
  await expect(plugin.imsLogin(gIms, gConfig)).rejects.toEqual(new Error('A passphrase is needed for your private-key. Use the --passphrase flag to specify one.'))
})

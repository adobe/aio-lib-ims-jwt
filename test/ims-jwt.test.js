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

const plugin = require('../src/ims-jwt')
const helpers = require('../src/helpers')

jest.mock('jsonwebtoken')
jest.mock('../src/helpers')

const gIms = {
  exchangeJwtToken: jest.fn(),
  getApiUrl: jest.fn()
}

const gConfig = {
  client_id: 'my-client-id',
  client_secret: 'my-client-secret',
  ims_org_id: 'my-ims-org-id',
  technical_account_id: 'my-tech-acct-id',
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

  helpers.createJwt.mockImplementation(() => {
    return myJwtToken
  })

  gIms.exchangeJwtToken.mockImplementation((clientId, clientSecret, jwtToken) => {
    expect(jwtToken).toEqual(myJwtToken)
    return myAccessToken
  })

  // normal acceptable config
  await expect(plugin.imsLogin(gIms, gConfig)).resolves.toEqual(myAccessToken)

  // config missing a property
  const configMissingProperties = Object.assign({}, gConfig)
  delete configMissingProperties.client_id
  await expect(plugin.imsLogin(gIms, configMissingProperties)).rejects.toEqual(new Error('JWT not supported due to some missing properties: client_id'))
})

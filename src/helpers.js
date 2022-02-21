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

const jwt = require('jsonwebtoken')
const aioLogger = require('@adobe/aio-lib-core-logging')('@adobe/aio-lib-ims-jwt')
const { HttpExponentialBackoff } = require('@adobe/aio-lib-core-networking')
const fs = require('fs') // need promises
const { codes: errors } = require('./errors')
const path = require('path')
const os = require('os')

const CONFIG_PATH = path.join(os.homedir(), '.config')

/**
 * Convert a string value to Json. Returns the original string if it fails.
 *
 * @private
 * @param {string} value the value to attempt conversion to Json
 * @returns {object|string} the converted json, or the original string
 */
function parseJson (value) {
  try {
    return JSON.parse(value)
  } catch (e) {
    return value
  }
}

/**
 * Checks that the input string or array starts with the private key prefix.
 *
 * @param {string|Array<string>} key the input key
 * @returns {boolean} the returned value
 * @private
 */
function isPrivateKey (key) {
  const PREFIX = '-----BEGIN'
  return (typeof key === 'string' && key.startsWith(PREFIX)) ||
          (Array.isArray(key) && key[0].startsWith(PREFIX))
}

/**
 * Reads a file from path and returns a promise resolving to the string content.
 *
 * @param {string} file path to the file
 * @returns {Promise<string>} resolves to the file content string
 * @private
 */
function readFileString (file) {
  // make it a promise, avoid unnecessary dependencies
  return new Promise((resolve, reject) => {
    fs.readFile(file, (err, data) => {
      if (err) {
        return reject(err)
      }
      return resolve(data.toString())
    })
  })
}

/**
 * Load local private key
 * @private
 * @param certName name of the private key
 * @returns {Buffer| undefined} privateKey
 */
function loadPrivateKey (certName) {
  if (certName) {
    const certLocation = path.join(CONFIG_PATH, certName)
    if (fs.existsSync(certLocation)) {
      aioLogger.debug('Private key loaded from: %s', certLocation)
      return fs.readFileSync(path.join(CONFIG_PATH, certName))
    }
  }
}
/**
 * Fetch new private key.
 * @private
 * @param {string} env IMS environment type
 * @param {string} certName Certificate name that can be used to verify the signature
 * @returns {Promise<string>} privateKey
 */
async function getPrivateKey (env, certName) {
  if (env && certName) {
    const URL = `https://static.adobelogin.com/keys/${env}/${certName}`
    const certLocation = path.join(CONFIG_PATH, certName)
    aioLogger.debug('Fetching a new private key...')
    const fetchRetry = new HttpExponentialBackoff()
    const res = await fetchRetry.exponentialBackoff(URL, {})
    const data = await res.text()
    /* istanbul ignore else */
    if (isPrivateKey(data)) {
      fs.writeFileSync(certLocation, data)
      aioLogger.debug('Private key saved at: %s', certLocation)
      return data
    }
  }
  aioLogger.debug('Invalid params %s, %s', env, certName)
  return Promise.reject(new Error('Invalid params.'))
}

/**
 * Validates provided token using an IMS public key cert.
 *
 * @param {string} token Jwt token you want to validate. It validates only the access_token type.
 * @returns {Promise<void>} Will throw if token is invalid
 */
async function verifyJwt (token) {
  try {
    const decoded = jwt.decode(token, { complete: true })
    const { x5u: certName } = decoded.header
    const { state, type } = decoded.payload
    if (type === 'access_token') {
      const { env } = JSON.parse(state)
      const cert = loadPrivateKey(certName) || await getPrivateKey(env, certName)
      jwt.verify(token, cert, { algorithms: ['RS256'] })
      aioLogger.debug('Access token is valid')
    }
  } catch (err) {
    aioLogger.debug('Error while validating token: %s', err)
    throw new errors.INVALID_TOKEN()
  }
}

/**
 * Create a jwt token.
 *
 * @private
 * @param {object} ims the Ims object
 * @param {string} clientId The client ID assigned to the integration
 * @param {string} imsOrg The IMS Org ID of the customer
 * @param {string} techacctId The Technical Account Id field of the integration
 * @param {string} metaScopes The secret associated to the client ID
 * @param {string} privateKey The private key associated with the integration
 * @param {string} [passphrase] The passphrase for the private key
 * @returns {Promise<string>} the jwt token
 */
async function createJwt (ims, clientId, imsOrg, techacctId, metaScopes, privateKey, passphrase) {
  // Prepare a short lived JWT token to exchange for an access token
  const payload = {
    exp: Math.round(Date.now() / 1000 + 300), // 5 minutes expiry time
    iss: imsOrg,
    sub: techacctId,
    aud: ims.getApiUrl('/c/' + clientId)
  }

  // configure the metascope for the JWT (only one supported for now)
  metaScopes = parseJson(metaScopes)
  for (const metaScope of metaScopes) {
    payload[ims.getApiUrl('/s/' + metaScope)] = true
  }

  const parsedPrivateKey = parseJson(privateKey)
  let keyParam
  if (isPrivateKey(parsedPrivateKey)) {
    keyParam = (typeof (parsedPrivateKey) === 'string') ? parsedPrivateKey : parsedPrivateKey.join('\n')
  } else {
    // attempt to read file from string
    keyParam = await readFileString(privateKey)
    if (!isPrivateKey(keyParam)) {
      throw new errors.INVALID_KEY_FILE({ messageValues: privateKey })
    }
  }

  if (passphrase) {
    keyParam = {
      key: keyParam,
      passphrase
    }
  }

  let jwtToken
  try {
    jwtToken = jwt.sign(payload, keyParam, { algorithm: 'RS256' }, null)
    aioLogger.debug('Signed JWT token: %s', jwtToken)
    return jwtToken
  } catch (err) {
    aioLogger.debug('JWT signing failed: %s', err.message)
    aioLogger.debug(err.stack)
    throw new errors.INVALID_KEY()
  }
}

module.exports = {
  parseJson,
  createJwt,
  verifyJwt
}

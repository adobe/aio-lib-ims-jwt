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
const fs = require('fs') // need promises
const { codes: errors } = require('./errors')

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
  createJwt
}

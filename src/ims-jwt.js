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

const jwt = require('jsonwebtoken');
const debug = require('debug')('@adobe/adobeio-cna-core-ims-jwt/login');

// The ims-login hook for JWT is taking care of calling IMS
// the function takes the

function canSupportSync(configData) {
  if (!configData) {
    return false;
  }

  const missing_keys = [];
  const required_keys = ['client_id', 'client_secret', 'techacct', 'meta_scopes', 'ims_org_id', 'private_key'];

  required_keys.forEach(key => {
    if (!configData[key]) {
      missing_keys.push(key)
    }
  })

  return missing_keys.length == 0;
}

async function canSupport(configData) {
  if (canSupportSync(configData)) {
    return Promise.resolve(true);
  } else {
    // TODO: Indicate that this is not really an error but just a possibility
    return Promise.reject(`JWT not supported due to some missing properties: ${missing_keys}`);
  }
}

async function createJwt(ims, clientId, imsOrg, techacct, metaScopes, privateKey, passphrase) {
  // new mechism: only JWT properties are in the configuration:
  // configData: An object providing the properties required for JWT with properties:
  //     imsOrg:        The IMS Org ID of the customer
  //     techacct:      The Technical Account field of the integration
  //     clientId:      The client ID assigned to the integration
  //     clientSecret:  The secret associated to the client ID
  //     metaScopes:    Array of IMS meta scope related to APIs integrated with
  //     secret:        The secret key corresponding to the public key
  //                    registered with the integration

  // Prepare a short lived JWT token to exchange for an access token
  const payload = {
    exp: Math.round(Date.now() / 1000 + 300),  // 5 minutes expiry time
    iss: imsOrg,
    sub: techacct,
    aud: ims.getApiUrl("/c/" + clientId)
  }

  // configure the metascope for the JWT (only one supported for now)
  for (const metaScope of metaScopes) {
    payload[ims.getApiUrl("/s/" + metaScope)] = true
  }

  let keyParam = (typeof(privateKey) === "string") ? privateKey : privateKey.join('\n');
  if (passphrase) {
    keyParam = {
      key: privateKey,
      passphrase
    }
  }

  let jwtToken
  try {
    jwtToken = jwt.sign(payload, keyParam, { algorithm: 'RS256' }, null);
    debug("Signed JWT token: %s", jwtToken);
    return jwtToken;
  } catch (err) {
    debug("JWT signing failed: %s", err.message);
    debug(err.stack);
    throw new Error('A passphrase is needed for your private-key. Use the --passphrase flag to specify one.')
  }
}

async function imsLogin(ims, config) {
  return canSupport(config)
    .then(() => createJwt(ims, config.client_id, config.ims_org_id, config.techacct, config.meta_scopes, config.private_key))
    .then(jwtToken => ims.exchangeJwtToken(config.client_id, config.client_secret, jwtToken))
}

module.exports = {
  supports: canSupportSync,
  imsLogin
}

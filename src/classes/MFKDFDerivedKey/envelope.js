/**
 * @file Multi-Factor Derived Key Enveloped Secret Functions
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Enveloped secret operations using a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const crypto = require('crypto')

/**
 * Add enveloped secret to a multi-factor derived key
 *
 * @param {string} id - String which uniquely identifies the enveloped secret to add
 * @param {Buffer} value - The plaintext secret value to be encrypted with this key
 * @param {string} [type='raw'] - The type of the enveloped secret to add
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.20.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function addEnvelopedSecret (id, value, type = 'raw') {
  if (typeof id !== 'string') throw new TypeError('id must be a string')
  if (!Buffer.isBuffer(value)) throw new TypeError('value must be a buffer')
  if (typeof type !== 'string') throw new TypeError('type must be a string')
  if (this.hasEnvelopedSecret(id)) throw new RangeError('id must be unique')
  if (!Array.isArray(this.policy.secrets)) this.policy.secrets = []

  const ct = await this.encrypt(value)

  this.policy.secrets.push({
    id,
    value: ct.toString('base64'),
    type
  })
}
module.exports.addEnvelopedSecret = addEnvelopedSecret

/**
 * Check if multi-factor derived key has enveloped secret with id
 *
 * @param {string} id - String which uniquely identifies the enveloped secret
 * @returns {boolean} - Whether the key has enveloped secret with given id
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.20.0
 * @memberOf MFKDFDerivedKey
 */
function hasEnvelopedSecret (id) {
  if (typeof id !== 'string') throw new TypeError('id must be a string')
  if (!Array.isArray(this.policy.secrets)) return false
  return this.policy.secrets.some(x => x.id === id)
}
module.exports.hasEnvelopedSecret = hasEnvelopedSecret

/**
 * Remove enveloped secret from a multi-factor derived key
 *
 * @param {string} id - ID of the enveloped secret to remove
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.20.0
 * @memberOf MFKDFDerivedKey
 */
function removeEnvelopedSecret (id) {
  if (typeof id !== 'string') throw new TypeError('id must be a string')
  if (!this.hasEnvelopedSecret(id)) throw new RangeError('secret with id does not exist')
  this.policy.secrets = this.policy.secrets.filter(x => x.id !== id)
}
module.exports.removeEnvelopedSecret = removeEnvelopedSecret

/**
 * Add enveloped key to a multi-factor derived key
 *
 * @param {string} id - String which uniquely identifies the enveloped key to add
 * @param {string} [type='rsa1024'] - The type of the enveloped key to add; rsa1024, rsa2048, or ed25519
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.20.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function addEnvelopedKey (id, type = 'rsa1024') {
  if (typeof id !== 'string') throw new TypeError('id must be a string')
  if (typeof type !== 'string') throw new TypeError('type must be a string')

  const options = {
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'der'
    }
  }

  let myType

  if (type === 'rsa1024') {
    myType = 'rsa'
    options.modulusLength = 1024
  } else if (type === 'rsa2048') {
    myType = 'rsa'
    options.modulusLength = 2048
  } else if (type === 'ed25519') {
    myType = 'ed25519'
  } else {
    throw new RangeError('invalid key type')
  }

  const keyPair = await crypto.generateKeyPairSync(myType, options)

  return await this.addEnvelopedSecret(id, keyPair.privateKey, type)
}
module.exports.addEnvelopedKey = addEnvelopedKey

/**
 * Get enveloped secret from a multi-factor derived key
 *
 * @param {string} id - ID of the enveloped secret to get
 * @returns {Buffer} The retrieved plaintext secret value
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.20.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function getEnvelopedSecret (id) {
  if (typeof id !== 'string') throw new TypeError('id must be a string')
  if (!this.hasEnvelopedSecret(id)) throw new RangeError('secret with id does not exist')
  const secret = this.policy.secrets.find(x => x.id === id)
  const ct = Buffer.from(secret.value, 'base64')
  return await this.decrypt(ct)
}
module.exports.getEnvelopedSecret = getEnvelopedSecret

/**
 * Get enveloped secret from a multi-factor derived key
 *
 * @param {string} id - ID of the enveloped key to get
 * @returns {PrivateKeyObject} The retrieved enveloped key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.20.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function getEnvelopedKey (id) {
  if (typeof id !== 'string') throw new TypeError('id must be a string')
  const privateKey = await this.getEnvelopedSecret(id)

  return await crypto.createPrivateKey({
    key: privateKey,
    format: 'der',
    type: 'pkcs8'
  })
}
module.exports.getEnvelopedKey = getEnvelopedKey

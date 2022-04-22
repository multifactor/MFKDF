/**
 * @file Multi-Factor Derived Key Crypto Functions
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Cryptographic operations for a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const { hkdf } = require('@panva/hkdf')
const crypto = require('crypto')
const getKeyPairFromSeed = require('human-crypto-keys').getKeyPairFromSeed

/**
 * Create a sub-key of specified size and purpose using HKDF.
 * @param {number} [size] - the size of sub-key to derive in bytes; same as base key by default
 * @param {string} [purpose=''] - factors used to derive this key
 * @param {string} [digest='sha512'] - HKDF digest to use; sha1, sha256, sha384, or sha512 (default)
 * @returns {Buffer} derived sub-key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @async
 */
async function getSubkey (size = this.policy.size, purpose = '', digest = 'sha512') {
  const result = await hkdf(digest, this.key, '', purpose, size)
  return Buffer.from(result)
}
module.exports.getSubkey = getSubkey

/**
 * Create a symmetric sub-key of specified type.
 * @param {string} [type='aes256'] - type of key to generate; des, 3des, aes128, aes192, or aes256 (default)ult)
 * @param {boolean} [auth=false] - whether this is being used for authentication
 * @returns {Buffer} derived sub-key as a Buffer
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @async
 */
async function getSymmetricKey (type = 'aes256', auth = false) {
  type = type.toLowerCase()
  if (type === 'des') { // DES
    return await this.getSubkey(8, auth ? 'DESAUTH' : 'DES', 'sha256')
  } else if (type === '3des') { // 3DES
    return await this.getSubkey(24, auth ? '3DESAUTH' : '3DES', 'sha256')
  } else if (type === 'aes128') { // AES 128
    return await this.getSubkey(16, auth ? 'AES128AUTH' : 'AES128', 'sha256')
  } else if (type === 'aes192') { // AES 192
    return await this.getSubkey(24, auth ? 'AES192AUTH' : 'AES192', 'sha256')
  } else if (type === 'aes256') { // AES 256
    return await this.getSubkey(32, auth ? 'AES256AUTH' : 'AES256', 'sha256')
  } else {
    throw new RangeError('unknown type: ' + type)
  }
}
module.exports.getSymmetricKey = getSymmetricKey

/**
 * Create an asymmetric sub-key pair of specified type.
 * @param {string} [type='rsa3072'] - type of key to generate; ed25519, rsa1024, rsa2048, or rsa3072 (default)
 * @returns {Object} spki-der encoded public key and pkcs8-der encoded private keyult)
 * @param {boolean} [auth=false] - whether this is being used for authentication
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.11.0
 * @async
 */
async function getAsymmetricKeyPair (type = 'rsa3072', auth = false) {
  type = type.toLowerCase()
  const format = { privateKeyFormat: 'pkcs8-der', publicKeyFormat: 'spki-der' }
  if (type === 'ed25519') { // ed25519
    const material = await this.getSubkey(32, auth ? 'ED25519AUTH' : 'ED25519', 'sha256')
    return await getKeyPairFromSeed(material, { id: 'ed25519' }, format)
  } else if (type === 'rsa1024') { // RSA 1024
    const material = await this.getSubkey(32, auth ? 'RSA1024AUTH' : 'RSA1024', 'sha256')
    return await getKeyPairFromSeed(material, { id: 'rsa', modulusLength: 1024 }, format)
  } else if (type === 'rsa2048') { // RSA 2048
    const material = await this.getSubkey(32, auth ? 'RSA2048AUTH' : 'RSA2048', 'sha256')
    return await getKeyPairFromSeed(material, { id: 'rsa', modulusLength: 2048 }, format)
  } else if (type === 'rsa3072') { // RSA 3072
    const material = await this.getSubkey(48, auth ? 'RSA3072AUTH' : 'RSA3072', 'sha256')
    return await getKeyPairFromSeed(material, { id: 'rsa', modulusLength: 3072 }, format)
  } else {
    throw new RangeError('unknown type: ' + type)
  }
}
module.exports.getAsymmetricKeyPair = getAsymmetricKeyPair

/**
 * Sign a message with this key.
 * @param {string|Buffer} message - the message to sign
 * @param {string} [method='rsa3072'] - signature method to use; rsa1024, rsa2048, or rsa3072 (default)ult)
 * @param {boolean} [auth=false] - whether this is being used for authentication
 * @returns {Buffer} the signed message
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.11.0
 * @async
 */
async function sign (message, method = 'rsa3072', auth = false) {
  if (typeof message === 'string') message = Buffer.from(message)
  if (!(Buffer.isBuffer(message))) throw new TypeError('message must be a buffer')
  method = method.toLowerCase()

  const key = await this.getAsymmetricKeyPair(method, auth)

  const cryptoKey = await crypto.webcrypto.subtle.importKey('pkcs8', key.privateKey, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'])
  const signature = await crypto.webcrypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, cryptoKey, message)

  return Buffer.from(signature)
}
module.exports.sign = sign

/**
 * Verify a message signed with this key.
 * @param {string|Buffer} message - the message this signature corresponds to
 * @param {Buffer} signature - the signature to verify
 * @param {string} [method='rsa3072'] - signature method to use; rsa1024, rsa2048, or rsa3072 (default)
 * @returns {boolean} whether the signature is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.11.0
 * @async
 */
async function verify (message, signature, method = 'rsa3072') {
  if (typeof message === 'string') message = Buffer.from(message)
  if (!(Buffer.isBuffer(message))) throw new TypeError('message must be a buffer')
  method = method.toLowerCase()

  const key = await this.getAsymmetricKeyPair(method)

  const cryptoKey = await crypto.webcrypto.subtle.importKey('spki', key.publicKey, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
  return await crypto.webcrypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, cryptoKey, signature, message)
}
module.exports.verify = verify

/**
 * Encrypt a message with this key.
 * @param {string|Buffer} message - the message to encrypt
 * @param {string} [method='aes256'] - encryption method to use; rsa1024, rsa2048, des, 3des, aes128, aes192, or aes256 (default)
 * @param {string} [mode='CBC'] - encryption mode to use; ECB, CFB, OFB, GCM, CTR, or CBC (default)
 * @param {boolean} [auth=false] - whether this is being used for authentication
 * @returns {Buffer} the encrypted message
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @async
 */
async function encrypt (message, method = 'aes256', mode = 'CBC', auth = false) {
  if (typeof message === 'string') message = Buffer.from(message)
  if (!(Buffer.isBuffer(message))) throw new TypeError('message must be a buffer')
  method = method.toLowerCase()
  mode = mode.toUpperCase()

  const key = (method === 'rsa1024' || method === 'rsa2048') ? await this.getAsymmetricKeyPair(method, auth) : await this.getSymmetricKey(method, auth)
  let cipher
  let iv

  if (method === 'rsa1024') { // RSA 1024
    const cryptoKey = await crypto.webcrypto.subtle.importKey('spki', key.publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt'])
    const ct = await crypto.webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, cryptoKey, message)
    return Buffer.from(ct)
  } else if (method === 'rsa2048') { // RSA 2048
    const cryptoKey = await crypto.webcrypto.subtle.importKey('spki', key.publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt'])
    const ct = await crypto.webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, cryptoKey, message)
    return Buffer.from(ct)
  } else if (method === 'des') { // DES
    iv = (mode === 'ECB') ? Buffer.from('') : crypto.randomBytes(8)
    cipher = crypto.createCipheriv('DES-' + mode, key, iv)
  } else if (method === '3des') { // 3DES
    iv = (mode === 'ECB') ? Buffer.from('') : crypto.randomBytes(8)
    cipher = crypto.createCipheriv('DES-EDE3-' + mode, key, iv)
  } else if (method === 'aes128') { // AES 128
    iv = (mode === 'ECB') ? Buffer.from('') : crypto.randomBytes(16)
    cipher = crypto.createCipheriv('AES-128-' + mode, key, iv)
  } else if (method === 'aes192') { // AES 192
    iv = (mode === 'ECB') ? Buffer.from('') : crypto.randomBytes(16)
    cipher = crypto.createCipheriv('AES-192-' + mode, key, iv)
  } else { // AES 256
    iv = (mode === 'ECB') ? Buffer.from('') : crypto.randomBytes(16)
    cipher = crypto.createCipheriv('AES-256-' + mode, key, iv)
  }

  return Buffer.concat([iv, cipher.update(message), cipher.final()])
}
module.exports.encrypt = encrypt

/**
 * Decrypt a message with this key.
 * @param {Buffer} message - the message to decrypt
 * @param {string} [method='aes256'] - decryption method to use; des, 3des, aes128, aes192, or aes256 (default)
 * @param {string} [mode='CBC'] - decryption mode to use; ECB, CFB, OFB, GCM, CTR, or CBC (default)
 * @returns {Buffer} the decrypted message
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @async
 */
async function decrypt (message, method = 'aes256', mode = 'CBC') {
  if (!(Buffer.isBuffer(message))) throw new TypeError('message must be a buffer')
  method = method.toLowerCase()
  mode = mode.toUpperCase()

  const key = (method === 'rsa1024' || method === 'rsa2048') ? await this.getAsymmetricKeyPair(method) : await this.getSymmetricKey(method)
  let decipher
  let iv
  let ct

  if (method === 'rsa1024') { // RSA 1024
    const cryptoKey = await crypto.webcrypto.subtle.importKey('pkcs8', key.privateKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt'])
    const ct = await crypto.webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, cryptoKey, message)
    return Buffer.from(ct)
  } else if (method === 'rsa2048') { // RSA 2048
    const cryptoKey = await crypto.webcrypto.subtle.importKey('pkcs8', key.privateKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt'])
    const ct = await crypto.webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, cryptoKey, message)
    return Buffer.from(ct)
  } else if (method === 'des') { // DES
    iv = (mode === 'ECB') ? '' : message.subarray(0, 8)
    ct = (mode === 'ECB') ? message : message.subarray(8)
    decipher = crypto.createDecipheriv('DES-' + mode, key, iv)
  } else if (method === '3des') { // 3DES
    iv = (mode === 'ECB') ? '' : message.subarray(0, 8)
    ct = (mode === 'ECB') ? message : message.subarray(8)
    decipher = crypto.createDecipheriv('DES-EDE3-' + mode, key, iv)
  } else if (method === 'aes128') { // AES 128
    iv = (mode === 'ECB') ? '' : message.subarray(0, 16)
    ct = (mode === 'ECB') ? message : message.subarray(16)
    decipher = crypto.createDecipheriv('AES-128-' + mode, key, iv)
  } else if (method === 'aes192') { // AES 192
    iv = (mode === 'ECB') ? '' : message.subarray(0, 16)
    ct = (mode === 'ECB') ? message : message.subarray(16)
    decipher = crypto.createDecipheriv('AES-192-' + mode, key, iv)
  } else { // AES 256
    iv = (mode === 'ECB') ? '' : message.subarray(0, 16)
    ct = (mode === 'ECB') ? message : message.subarray(16)
    decipher = crypto.createDecipheriv('AES-256-' + mode, key, iv)
  }

  // decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(ct), decipher.final()])
}
module.exports.decrypt = decrypt

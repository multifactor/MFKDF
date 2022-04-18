/**
 * @file Multi-Factor Derived Key Class
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Class representing a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const { hkdf } = require('@panva/hkdf')
const crypto = require('crypto')
const getKeyPairFromSeed = require('human-crypto-keys').getKeyPairFromSeed

/**
 * Class representing a multi-factor derived key.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.8.0
 */
class MFKDFDerivedKey {
  /**
   * Create a MFKDFDerivedKey object.
   * @param {Object} policy - The policy for deriving this key.
   * @param {Buffer} key - The value of this derived key.
   */
  constructor (policy, key) {
    this.policy = policy
    this.key = key
  }

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
  async getSubkey (size = this.policy.size, purpose = '', digest = 'sha512') {
    const result = await hkdf(digest, this.key, '', purpose, size)
    return Buffer.from(result)
  }

  /**
   * Create a symmetric sub-key of specified type.
   * @param {string} [type='aes256'] - type of key to generate; des, 3des, aes128, aes192, or aes256 (default)
   * @returns {Buffer} derived sub-key as a Buffer
   * @author Vivek Nair (https://nair.me) <vivek@nair.me>
   * @since 0.10.0
   * @async
   */
  async getSymmetricKey (type = 'aes256') {
    type = type.toLowerCase()
    if (type === 'des') { // DES
      return await this.getSubkey(8, 'DES', 'sha256')
    } else if (type === '3des') { // 3DES
      return await this.getSubkey(24, '3DES', 'sha256')
    } else if (type === 'aes128') { // AES 128
      return await this.getSubkey(16, 'AES128', 'sha256')
    } else if (type === 'aes192') { // AES 192
      return await this.getSubkey(24, 'AES192', 'sha256')
    } else if (type === 'aes256') { // AES 256
      return await this.getSubkey(32, 'AES256', 'sha256')
    } else {
      throw new RangeError('unknown type: ' + type)
    }
  }

  /**
   * Create an asymmetric sub-key pair of specified type.
   * @param {string} [type='aes256'] - type of key to generate; ed25519, rsa1024, rsa2048, rsa3072, or rsa4096 (default)
   * @returns {Object} spki-pem encoded public key and pkcs8-pem encoded private key
   * @author Vivek Nair (https://nair.me) <vivek@nair.me>
   * @since 0.10.0
   * @async
   */
  async getAsymmetricKeyPair (type = 'rsa4096') {
    type = type.toLowerCase()
    if (type === 'ed25519') { // ed25519
      const material = await this.getSubkey(32, 'ED25519', 'sha256')
      return await getKeyPairFromSeed(material, { id: 'ed25519' })
    } else if (type === 'rsa1024') { // RSA 1024
      const material = await this.getSubkey(32, 'RSA1024', 'sha256')
      return await getKeyPairFromSeed(material, { id: 'rsa', modulusLength: 1024 })
    } else if (type === 'rsa2048') { // RSA 2048
      const material = await this.getSubkey(32, 'RSA2048', 'sha256')
      return await getKeyPairFromSeed(material, { id: 'rsa', modulusLength: 2048 })
    } else if (type === 'rsa3072') { // RSA 3072
      const material = await this.getSubkey(48, 'RSA3072', 'sha256')
      return await getKeyPairFromSeed(material, { id: 'rsa', modulusLength: 3072 })
    } else if (type === 'rsa4096') { // RSA 4096
      const material = await this.getSubkey(64, 'RSA4096', 'sha256')
      return await getKeyPairFromSeed(material, { id: 'rsa', modulusLength: 4096 })
    } else {
      throw new RangeError('unknown type: ' + type)
    }
  }

  /**
   * Encrypt a message with this key.
   * @param {string|Buffer} message - the message to encrypt
   * @param {string} [method='aes256'] - encryption method to use; des, 3des, aes128, aes192, or aes256 (default)
   * @param {string} [mode='CBC'] - encryption mode to use; ECB, CFB, OFB, GCM, CTR, or CBC (default)
   * @returns {Buffer} the encrypted message
   * @author Vivek Nair (https://nair.me) <vivek@nair.me>
   * @since 0.10.0
   * @async
   */
  async encrypt (message, method = 'aes256', mode = 'CBC') {
    if (typeof message === 'string') message = Buffer.from(message)
    if (!(Buffer.isBuffer(message))) throw new TypeError('message must be a buffer')
    method = method.toLowerCase()
    mode = mode.toUpperCase()

    const key = await this.getSymmetricKey(method)
    let cipher
    let iv

    if (method === 'des') { // DES
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
  async decrypt (message, method = 'aes256', mode = 'CBC') {
    if (!(Buffer.isBuffer(message))) throw new TypeError('message must be a buffer')
    method = method.toLowerCase()
    mode = mode.toUpperCase()

    const key = await this.getSymmetricKey(method)
    let decipher
    let iv
    let ct

    if (method === 'des') { // DES
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
}

module.exports = MFKDFDerivedKey

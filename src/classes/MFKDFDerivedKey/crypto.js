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
let subtle
/* istanbul ignore next */
if (typeof window !== 'undefined') {
  subtle = window.crypto.subtle
} else {
  subtle = crypto.webcrypto.subtle
}

/**
 * Create a sub-key of specified size and purpose using HKDF
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // get 16-byte sub-key for "eth" using hkdf/sha256
 * const subkey = await key.getSubkey(16, 'eth', 'sha256')
 * subkey.toString('hex') // -> 54ad9e5acbc1c33b08a15dd79126e9c9
 *
 * @param {number} [size] - The size of sub-key to derive in bytes; same as base key by default
 * @param {string} [purpose=''] - Factors used to derive this key
 * @param {string} [digest='sha512'] - HKDF digest to use; sha1, sha256, sha384, or sha512
 * @returns {Buffer} Derived sub-key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function getSubkey (
  size = this.policy.size,
  purpose = '',
  digest = 'sha512'
) {
  const tag = digest + ';' + size + ';' + purpose
  if (this.subkeys[tag]) return this.subkeys[tag]
  const result = Buffer.from(await hkdf(digest, this.key, '', purpose, size))
  this.subkeys[tag] = result
  return result
}
module.exports.getSubkey = getSubkey

/**
 * Create a symmetric sub-key of specified type
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // get 16-byte AES128 sub-key
 * const subkey = await key.getSymmetricKey('aes128')
 * subkey.toString('hex') // -> c985454e008e5ecc695e865d339cb2be
 *
 * @param {string} [type='aes256'] - Type of key to generate; des, 3des, aes128, aes192, or aes256
 * @param {boolean} [auth=false] - Whether this is being used for authentication
 * @returns {Buffer} Derived sub-key as a Buffer
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @memberOf MFKDFDerivedKey
 * @async
 * @deprecated
 */
async function getSymmetricKey (type = 'aes256', auth = false) {
  type = type.toLowerCase()
  if (type === 'des') {
    // DES
    return await this.getSubkey(8, auth ? 'DESAUTH' : 'DES', 'sha256')
  } else if (type === '3des') {
    // 3DES
    return await this.getSubkey(24, auth ? '3DESAUTH' : '3DES', 'sha256')
  } else if (type === 'aes128') {
    // AES 128
    return await this.getSubkey(16, auth ? 'AES128AUTH' : 'AES128', 'sha256')
  } else if (type === 'aes192') {
    // AES 192
    return await this.getSubkey(24, auth ? 'AES192AUTH' : 'AES192', 'sha256')
  } else if (type === 'aes256') {
    // AES 256
    return await this.getSubkey(32, auth ? 'AES256AUTH' : 'AES256', 'sha256')
  } else {
    throw new RangeError('unknown type: ' + type)
  }
}
module.exports.getSymmetricKey = getSymmetricKey

/**
 * Create an asymmetric sub-key pair of specified type
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // get 16-byte RSA1024 sub-key
 * const subkey = await key.getAsymmetricKeyPair('rsa1024') // -> { privateKey: Uint8Array, publicKey: Uint8Array }
 *
 * @param {string} [type='rsa3072'] - Type of key to generate; ed25519, rsa1024, rsa2048, or rsa3072
 * @param {boolean} [auth=false] - Whether this is being used for authentication
 * @returns {Object} Public key (spki-der encoded) and private key (pkcs8-der encoded)
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.11.0
 * @memberOf MFKDFDerivedKey
 * @async
 * @deprecated
 */
async function getAsymmetricKeyPair (type = 'rsa3072', auth = false) {
  type = type.toLowerCase()
  const format = { privateKeyFormat: 'pkcs8-der', publicKeyFormat: 'spki-der' }
  if (type === 'ed25519') {
    // ed25519
    const material = await this.getSubkey(
      32,
      auth ? 'ED25519AUTH' : 'ED25519',
      'sha256'
    )
    return await getKeyPairFromSeed(material, { id: 'ed25519' }, format)
  } else if (type === 'rsa1024') {
    // RSA 1024
    const material = await this.getSubkey(
      32,
      auth ? 'RSA1024AUTH' : 'RSA1024',
      'sha256'
    )
    return await getKeyPairFromSeed(
      material,
      { id: 'rsa', modulusLength: 1024 },
      format
    )
  } else if (type === 'rsa2048') {
    // RSA 2048
    const material = await this.getSubkey(
      32,
      auth ? 'RSA2048AUTH' : 'RSA2048',
      'sha256'
    )
    return await getKeyPairFromSeed(
      material,
      { id: 'rsa', modulusLength: 2048 },
      format
    )
  } else if (type === 'rsa3072') {
    // RSA 3072
    const material = await this.getSubkey(
      48,
      auth ? 'RSA3072AUTH' : 'RSA3072',
      'sha256'
    )
    return await getKeyPairFromSeed(
      material,
      { id: 'rsa', modulusLength: 3072 },
      format
    )
  } else {
    throw new RangeError('unknown type: ' + type)
  }
}
module.exports.getAsymmetricKeyPair = getAsymmetricKeyPair

/**
 * Sign a message with this key
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // sign message using RSA-1024
 * const signature = await key.sign('hello world', 'rsa1024')
 *
 * // verify signature using RSA-1024
 * const valid = await key.verify('hello world', signature, 'rsa1024') // -> true
 *
 * @param {string|Buffer} message - The message to sign
 * @param {string} [method='rsa3072'] - Signature method to use; rsa1024, rsa2048, or rsa3072
 * @param {boolean} [auth=false] - Whether this is being used for authentication
 * @returns {Buffer} The signed message
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.11.0
 * @memberOf MFKDFDerivedKey
 * @async
 * @deprecated
 */
async function sign (message, method = 'rsa3072', auth = false) {
  if (typeof message === 'string') message = Buffer.from(message)
  if (!Buffer.isBuffer(message)) { throw new TypeError('message must be a buffer') }
  method = method.toLowerCase()

  const key = await this.getAsymmetricKeyPair(method, auth)

  const cryptoKey = await subtle.importKey(
    'pkcs8',
    key.privateKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const signature = await subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    cryptoKey,
    message
  )

  return Buffer.from(signature)
}
module.exports.sign = sign

/**
 * Verify a message signed with this key
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // sign message using RSA-1024
 * const signature = await key.sign('hello world', 'rsa1024')
 *
 * // verify signature using RSA-1024
 * const valid = await key.verify('hello world', signature, 'rsa1024') // -> true
 *
 * @param {string|Buffer} message - The message this signature corresponds to
 * @param {Buffer} signature - The signature to verify
 * @param {string} [method='rsa3072'] - Signature method to use; rsa1024, rsa2048, or rsa3072
 * @returns {boolean} Whether the signature is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.11.0
 * @memberOf MFKDFDerivedKey
 * @async
 * @deprecated
 */
async function verify (message, signature, method = 'rsa3072') {
  if (typeof message === 'string') message = Buffer.from(message)
  if (!Buffer.isBuffer(message)) { throw new TypeError('message must be a buffer') }
  method = method.toLowerCase()

  const key = await this.getAsymmetricKeyPair(method)

  const cryptoKey = await subtle.importKey(
    'spki',
    key.publicKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  )
  return await subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    cryptoKey,
    signature,
    message
  )
}
module.exports.verify = verify

/**
 * Encrypt a message with this key
 *
 * Note: DES is not supported on Node.js v18 and later
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // encrypt message using 3DES
 * const encrypted = await key.encrypt('hello world', '3des')
 *
 * // decrypt message using 3DES
 * const decrypted = await key.decrypt(encrypted, '3des')
 * decrypted.toString() // -> hello world
 *
 * @param {string|Buffer} message - The message to encrypt
 * @param {string} [method='aes256'] - Encryption method to use; rsa1024, rsa2048, des, 3des, aes128, aes192, or aes256
 * @param {string} [mode='CBC'] - Encryption mode to use; ECB, CFB, OFB, GCM, CTR, or CBC
 * @param {boolean} [auth=false] - Whether this is being used for authentication
 * @returns {Buffer} The encrypted message
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @memberOf MFKDFDerivedKey
 * @async
 * @deprecated
 */
async function encrypt (message, method = 'aes256', mode = 'CBC', auth = false) {
  if (typeof message === 'string') message = Buffer.from(message)
  if (!Buffer.isBuffer(message)) { throw new TypeError('message must be a buffer') }
  method = method.toLowerCase()
  mode = mode.toUpperCase()

  const key =
    method === 'rsa1024' || method === 'rsa2048'
      ? await this.getAsymmetricKeyPair(method, auth)
      : await this.getSymmetricKey(method, auth)
  let cipher
  let iv

  if (method === 'rsa1024') {
    // RSA 1024
    const cryptoKey = await subtle.importKey(
      'spki',
      key.publicKey,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    )
    const ct = await subtle.encrypt({ name: 'RSA-OAEP' }, cryptoKey, message)
    return Buffer.from(ct)
  } else if (method === 'rsa2048') {
    // RSA 2048
    const cryptoKey = await subtle.importKey(
      'spki',
      key.publicKey,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    )
    const ct = await subtle.encrypt({ name: 'RSA-OAEP' }, cryptoKey, message)
    return Buffer.from(ct)
  } /* istanbul ignore if */ else if (method === 'des') {
    // DES
    iv = mode === 'ECB' ? Buffer.from('') : crypto.randomBytes(8)
    cipher = crypto.createCipheriv('DES-' + mode, key, iv)
  } else if (method === '3des') {
    // 3DES
    iv = mode === 'ECB' ? Buffer.from('') : crypto.randomBytes(8)
    cipher = crypto.createCipheriv('DES-EDE3-' + mode, key, iv)
  } else if (method === 'aes128') {
    // AES 128
    iv = mode === 'ECB' ? Buffer.from('') : crypto.randomBytes(16)
    cipher = crypto.createCipheriv('AES-128-' + mode, key, iv)
  } else if (method === 'aes192') {
    // AES 192
    iv = mode === 'ECB' ? Buffer.from('') : crypto.randomBytes(16)
    cipher = crypto.createCipheriv('AES-192-' + mode, key, iv)
  } else {
    // AES 256
    iv = mode === 'ECB' ? Buffer.from('') : crypto.randomBytes(16)
    cipher = crypto.createCipheriv('AES-256-' + mode, key, iv)
  }

  return Buffer.concat([iv, cipher.update(message), cipher.final()])
}
module.exports.encrypt = encrypt

/**
 * Decrypt a message with this key
 *
 * Note: DES is not supported on Node.js v18 and later
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // encrypt message using 3DES
 * const encrypted = await key.encrypt('hello world', '3des')
 *
 * // decrypt message using 3DES
 * const decrypted = await key.decrypt(encrypted, '3des')
 * decrypted.toString() // -> hello world
 *
 * @param {Buffer} message - The message to decrypt
 * @param {string} [method='aes256'] - Decryption method to use; des, 3des, aes128, aes192, or aes256
 * @param {string} [mode='CBC'] - Decryption mode to use; ECB, CFB, OFB, GCM, CTR, or CBC
 * @returns {Buffer} The decrypted message
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.10.0
 * @memberOf MFKDFDerivedKey
 * @async
 * @deprecated
 */
async function decrypt (message, method = 'aes256', mode = 'CBC') {
  if (!Buffer.isBuffer(message)) { throw new TypeError('message must be a buffer') }
  method = method.toLowerCase()
  mode = mode.toUpperCase()

  const key =
    method === 'rsa1024' || method === 'rsa2048'
      ? await this.getAsymmetricKeyPair(method)
      : await this.getSymmetricKey(method)
  let decipher
  let iv
  let ct

  if (method === 'rsa1024') {
    // RSA 1024
    const cryptoKey = await subtle.importKey(
      'pkcs8',
      key.privateKey,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    )
    const ct = await subtle.decrypt({ name: 'RSA-OAEP' }, cryptoKey, message)
    return Buffer.from(ct)
  } else if (method === 'rsa2048') {
    // RSA 2048
    const cryptoKey = await subtle.importKey(
      'pkcs8',
      key.privateKey,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    )
    const ct = await subtle.decrypt({ name: 'RSA-OAEP' }, cryptoKey, message)
    return Buffer.from(ct)
  } /* istanbul ignore if */ else if (method === 'des') {
    // DES
    iv = mode === 'ECB' ? '' : message.subarray(0, 8)
    ct = mode === 'ECB' ? message : message.subarray(8)
    decipher = crypto.createDecipheriv('DES-' + mode, key, iv)
  } else if (method === '3des') {
    // 3DES
    iv = mode === 'ECB' ? '' : message.subarray(0, 8)
    ct = mode === 'ECB' ? message : message.subarray(8)
    decipher = crypto.createDecipheriv('DES-EDE3-' + mode, key, iv)
  } else if (method === 'aes128') {
    // AES 128
    iv = mode === 'ECB' ? '' : message.subarray(0, 16)
    ct = mode === 'ECB' ? message : message.subarray(16)
    decipher = crypto.createDecipheriv('AES-128-' + mode, key, iv)
  } else if (method === 'aes192') {
    // AES 192
    iv = mode === 'ECB' ? '' : message.subarray(0, 16)
    ct = mode === 'ECB' ? message : message.subarray(16)
    decipher = crypto.createDecipheriv('AES-192-' + mode, key, iv)
  } else {
    // AES 256
    iv = mode === 'ECB' ? '' : message.subarray(0, 16)
    ct = mode === 'ECB' ? message : message.subarray(16)
    decipher = crypto.createDecipheriv('AES-256-' + mode, key, iv)
  }

  // decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(ct), decipher.final()])
}
module.exports.decrypt = decrypt

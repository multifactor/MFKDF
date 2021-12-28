/**
 * @file Multi-Factor Key Derivation Function (MFKDF)
 * @copyright Multifactor 2021 All Rights Reserved
 *
 * @description
 * JavaScript Implementation of a Multi-Factor Key Derivation Function (MFKDF)
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const config = require('./config')
const kdf = require('./kdf')
const secrets = require('secrets.js-grempe')
const pbkdf2 = require('pbkdf2')
const xor = require('buffer-xor')

/**
  * Derive a key from multiple factors of input.
  *
  * @example
  * // derive key using 2 of 3 factors
  * const mfkdf = require('mfkdf');
  * const key = await mfkdf.derive({
  *   password1: await mfkdf.factors.password('password1'),
  *   password3: await mfkdf.factors.password('password3')
  * }, config);
  *
  * @param {Object} factors - The factors from which a key should be derived.
  * @param {Object} config - The key derivation configuration produced by {@link setup}.
  * @param {Object} options - KDF options - see {@link kdf}.
  * @returns The derived key (as a Buffer).
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.2.0
  * @async
  */
module.exports.derive = async function derive (factors, config, options) {
  if (typeof config !== 'object') throw new TypeError('config must be an object')
  if (typeof config.t !== 'number') throw new TypeError('config.t must be a number')
  if (config.t < 1) throw new RangeError('threshold cannot be less than 1')
  if (typeof factors !== 'object') throw new TypeError('factors must be an object')
  if (Object.keys(factors).length < config.t) throw new RangeError('insufficient factors provided to derive a key (factors < threshold)')

  options = Object.assign(Object.assign({}, config.setup), options)
  const shares = []

  for (const [key, value] of Object.entries(factors)) {
    const maskedShare = Buffer.from(config.p[key], 'hex')
    const mask = await stretch(value, Buffer.byteLength(maskedShare))
    const share = xor(maskedShare, mask)
    const index = Object.keys(config.p).indexOf(key) + 1
    const fullShare = '8' + index.toString(16).padStart(2, '0') + share.toString('hex')
    shares.push(fullShare)
  }

  const secret = secrets.combine(shares)
  const key = await kdf.kdf(secret, config.s, options)

  return key
}

/**
  * Setup a new MFKDF-derived key.
  *
  * @example
  * // Setup key where any 2 of 3 passwords can be used to derive
  * const mfkdf = require('mfkdf');
  * const {key, config} = await mfkdf.setup({
  *   password1: await mfkdf.factors.password('password1'),
  *   password2: await mfkdf.factors.password('password2'),
  *   password3: await mfkdf.factors.password('password3')
  * }, 2);
  *
  * @param {Object} factors - The factors from which a key should be derived.
  * @param {number} threshold - The number of factors which should be required.
  * @param {Object} options - KDF options - see {@link kdf}.
  * @returns The derived key (as a Buffer) and the key derivation configuration needed to reproduce this key.
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.2.0
  * @async
  */
module.exports.setup = async function setup (factors, threshold = 0, options) {
  if (typeof threshold !== 'number' || !Number.isInteger(threshold)) throw new TypeError('threshold must be a number')
  if (typeof factors !== 'object') throw new TypeError('factors must be an object')
  if (Object.keys(factors).length < 2) throw new RangeError('must provide at least two factors for multi-factor key derivation')
  if (threshold === 0) threshold = Object.keys(factors).length
  if (threshold < 1) throw new RangeError('threshold cannot be less than 1')
  if (threshold > Object.keys(factors).length) throw new RangeError('threshold cannot be greater than number of provided factors')

  options = Object.assign(Object.assign({}, config.setup), options)

  const secret = secrets.random(options.size * 8)
  const shares = secrets.share(secret, Object.keys(factors).length, threshold)
  const pads = {}

  for (const [index, [key, value]] of Object.entries(Object.entries(factors))) {
    const components = secrets.extractShareComponents(shares[index])
    const share = Buffer.from(components.data, 'hex')
    const mask = await stretch(value, Buffer.byteLength(share))
    const maskedShare = xor(share, mask)
    pads[key] = maskedShare.toString('hex')
  }

  const salt = secrets.random(options.size * 8)
  const key = await kdf.kdf(secret, salt, options)

  return { key: key, config: { t: threshold, s: salt, p: pads } }
}

/**
  * Stretch a secret to a desired length.
  * Uses pbkdf2-sha512 under the hood.
  *
  * @example
  * // stretch 8B secret to 16B
  * const mfkdf = require('mfkdf');
  * const stretched = await mfkdf.stretch('9e26857e1d0a121f', 16);
  * console.log(stretched.toString('hex')); // c4b871e1edebc2907de74535a3d2bff2
  *
  * @param {string | Buffer} input - The input to stretch.
  * @param {number} length - The desired output length in bytes.
  * @returns Input stretched to desired length with pbkdf2-sha512.
  * @author Vivek Nair (https://nair.me) <vivek@nair.me>
  * @since 0.2.0
  * @async
  */
async function stretch (input, length) {
  return new Promise((resolve, reject) => {
    pbkdf2.pbkdf2(input, '', 1, length, 'sha512', (err, derivedKey) => {
      if (err) reject(err)
      else resolve(derivedKey)
    })
  })
}
module.exports.stretch = stretch

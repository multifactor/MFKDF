/**
 * @file MFKDF Recovery Code Factor
 * @copyright Multifactor 2021 All Rights Reserved
 *
 * @description
 * Secure uuidv4 recovery code factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const config = require('../config')
const pbkdf2 = require('pbkdf2')
const { validate: uuidValidate, version: uuidVersion, parse: uuidParse } = require('uuid')

/**
 * Derive a MFKDF factor from a uuidv4 recovery code.
 *
 * @example
 * // derive a 128b MFKDF factor from a uuidv4 recovery code
 * const mfkdf = require('mfkdf');
 * const recoveryCodeFactor = await mfkdf.factors.recoveryCode(
 *   '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
 *   {size: 16}
 * );
 * console.log(recoveryCodeFactor.toString('hex')); // 51766dfd9a56d3faa51b263796747a94
 *
 * @param {string} code - The uuidv4 code from which to derive an MFKDF factor.
 * @param {Object} [options] - MFKDF factor configuration options
 * @param {number} [options.size=32] - size of key material to return, in bytes
 * @param {string} [options.digest=sha256] - hash function to use; see crypto.getHashes() for options
 * @param {string} [options.salt=''] - recovery code salt to use; using no salt is acceptable if overall MFKDF uses a salt
 * @returns Derived MFKDF key material as a Buffer.
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.4.0
 * @async
 */
module.exports.recoveryCode = async function recoveryCode (code, options) {
  options = Object.assign(Object.assign({}, config.recoveryCodeFactor), options)

  if (!uuidValidate(code)) throw new TypeError('recovery code is not a valid uuid')
  if (uuidVersion(code) !== 4) throw new TypeError('recovery code is not a valid uuidv4')

  return new Promise((resolve, reject) => {
    const buffer = Buffer.from(uuidParse(code))
    pbkdf2.pbkdf2(buffer, options.salt, 1, options.size, options.digest, (err, derivedKey) => {
      if (err) reject(err)
      else resolve(derivedKey)
    })
  })
}

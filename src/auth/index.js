/**
 * Authentication functions
 *
 * @namespace auth
 */

const crypto = require('crypto')

/**
 * Verify ISO 9798-2 2-Pass Unilateral Authentication
 * @param {Buffer} challenge - The nonce value provided by the challenger
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @async
 */
async function VerifyISO97982PassUnilateralAuthSymmetric (challenge, identity, response, key) {
  const plaintext = Buffer.concat([challenge, identity])

  const iv = response.subarray(0, 16)
  const ct = response.subarray(16)
  const decipher = crypto.createDecipheriv('AES-256-CBC', key, iv)

  let decrypted
  try {
    decrypted = Buffer.concat([decipher.update(ct), decipher.final()])
  } catch (e) {
    return false
  }

  return (plaintext.toString('hex') === decrypted.toString('hex'))
}
module.exports.VerifyISO97982PassUnilateralAuthSymmetric = VerifyISO97982PassUnilateralAuthSymmetric

/**
 * Verify ISO 9798-2 Public Key 2-Pass Unilateral Authentication
 * @param {Buffer} challenge - The nonce value provided by the challenger
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @async
 */
async function VerifyISO97982PassUnilateralAuthAsymmetric (challenge, identity, response, key) {
  const plaintext = Buffer.concat([challenge, identity])

  const cryptoKey = await crypto.webcrypto.subtle.importKey('spki', key, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
  return await crypto.webcrypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, cryptoKey, response, plaintext)
}
module.exports.VerifyISO97982PassUnilateralAuthAsymmetric = VerifyISO97982PassUnilateralAuthAsymmetric

/**
 * Verify ISO 9798-2 2-Pass Unilateral Authentication over CCF
 * @param {Buffer} challenge - The nonce value provided by the challenger
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @async
 */
async function VerifyISO97982PassUnilateralAuthCCF (challenge, identity, response, key) {
  const ct = Buffer.concat([challenge, identity, key])
  const hash = crypto.createHash('sha256').update(ct).digest()
  return (hash.toString('hex') === response.toString('hex'))
}
module.exports.VerifyISO97982PassUnilateralAuthCCF = VerifyISO97982PassUnilateralAuthCCF

/**
 * Verify ISO 9798-2 1-Pass Unilateral Authentication
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @param {number} [window=5] - The maximum time difference in seconds
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @async
 */
async function VerifyISO97981PassUnilateralAuthSymmetric (identity, response, key, window = 5) {
  const challenge = response.subarray(0, 4)
  const value = response.subarray(4)

  const actual = Math.floor(Date.now() / 1000)
  const observed = challenge.readUInt32BE(0)
  if (Math.abs(actual - observed) > window) return false

  return await VerifyISO97982PassUnilateralAuthSymmetric(challenge, identity, value, key)
}
module.exports.VerifyISO97981PassUnilateralAuthSymmetric = VerifyISO97981PassUnilateralAuthSymmetric

/**
 * Verify ISO 9798-2 Public Key 1-Pass Unilateral Authentication
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @param {number} [window=5] - The maximum time difference in seconds
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @async
 */
async function VerifyISO97981PassUnilateralAuthAsymmetric (identity, response, key, window = 5) {
  const challenge = response.subarray(0, 4)
  const value = response.subarray(4)

  const actual = Math.floor(Date.now() / 1000)
  const observed = challenge.readUInt32BE(0)
  if (Math.abs(actual - observed) > window) return false

  return await VerifyISO97982PassUnilateralAuthAsymmetric(challenge, identity, value, key)
}
module.exports.VerifyISO97981PassUnilateralAuthAsymmetric = VerifyISO97981PassUnilateralAuthAsymmetric

/**
 * Verify ISO 9798-2 1-Pass Unilateral Authentication over CCF
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @param {number} [window=5] - The maximum time difference in seconds
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @async
 */
async function VerifyISO97981PassUnilateralAuthCCF (identity, response, key, window = 5) {
  const challenge = response.subarray(0, 4)
  const value = response.subarray(4)

  const actual = Math.floor(Date.now() / 1000)
  const observed = challenge.readUInt32BE(0)
  if (Math.abs(actual - observed) > window) return false

  return await VerifyISO97982PassUnilateralAuthCCF(challenge, identity, value, key)
}
module.exports.VerifyISO97981PassUnilateralAuthCCF = VerifyISO97981PassUnilateralAuthCCF

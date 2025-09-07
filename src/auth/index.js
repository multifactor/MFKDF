/**
 * Authentication functions
 *
 * @namespace auth
 */

const crypto = require('crypto')
let subtle
/* istanbul ignore next */
if (typeof window !== 'undefined') {
  subtle = window.crypto.subtle
} else {
  subtle = crypto.webcrypto.subtle
}

/**
 * Verify ISO 9798-2 2-Pass Unilateral Authentication
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])

 * // challenger: create random challenge
 * const challenge = crypto.randomBytes(32)
 * const identity = Buffer.from('Challenger')

 * // responder: generate response
 * const response = await key.ISO97982PassUnilateralAuthSymmetric(challenge, identity)

 * // verifier: verify response
 * const authKey = await key.ISO9798SymmetricKey()
 * const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthSymmetric(challenge, identity, response, authKey) // -> true
 *
 * @param {Buffer} challenge - The nonce value provided by the challenger
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf auth
 * @async
 * @deprecated
 */
async function VerifyISO97982PassUnilateralAuthSymmetric (
  challenge,
  identity,
  response,
  key
) {
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

  return plaintext.toString('hex') === decrypted.toString('hex')
}
module.exports.VerifyISO97982PassUnilateralAuthSymmetric =
  VerifyISO97982PassUnilateralAuthSymmetric

/**
 * Verify ISO 9798-2 Public Key 2-Pass Unilateral Authentication
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // challenger: create random challenge
 * const challenge = crypto.randomBytes(32)
 * const identity = Buffer.from('Challenger')
 *
 * // responder: generate response
 * const response = await key.ISO97982PassUnilateralAuthAsymmetric(challenge, identity)
 *
 * // verifier: verify response
 * const authKey = await key.ISO9798AsymmetricKey()
 * const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthAsymmetric(challenge, identity, response, authKey) // -> true
 *
 * @param {Buffer} challenge - The nonce value provided by the challenger
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf auth
 * @async
 * @deprecated
 */
async function VerifyISO97982PassUnilateralAuthAsymmetric (
  challenge,
  identity,
  response,
  key
) {
  const plaintext = Buffer.concat([challenge, identity])

  const cryptoKey = await subtle.importKey(
    'spki',
    key,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  )
  return await subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    cryptoKey,
    response,
    plaintext
  )
}
module.exports.VerifyISO97982PassUnilateralAuthAsymmetric =
  VerifyISO97982PassUnilateralAuthAsymmetric

/**
 * Verify ISO 9798-2 2-Pass Unilateral Authentication over CCF
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 *
 * // challenger: create random challenge
 * const challenge = crypto.randomBytes(32)
 * const identity = Buffer.from('Challenger')
 *
 * // responder: generate response
 * const response = await key.ISO97982PassUnilateralAuthCCF(challenge, identity)
 *
 * // verifier: verify response
 * const authKey = await key.ISO9798CCFKey()
 * const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthCCF(challenge, identity, response, authKey) // -> true
 *
 * @param {Buffer} challenge - The nonce value provided by the challenger
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf auth
 * @async
 * @deprecated
 */
async function VerifyISO97982PassUnilateralAuthCCF (
  challenge,
  identity,
  response,
  key
) {
  const ct = Buffer.concat([challenge, identity, key])
  const hash = crypto.createHash('sha256').update(ct).digest()
  return hash.toString('hex') === response.toString('hex')
}
module.exports.VerifyISO97982PassUnilateralAuthCCF =
  VerifyISO97982PassUnilateralAuthCCF

/**
 * Verify ISO 9798-2 1-Pass Unilateral Authentication
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 * const identity = Buffer.from('Challenger')
 *
 * // responder: generate response
 * const response = await key.ISO97981PassUnilateralAuthSymmetric(identity)
 *
 * // verifier: verify response
 * const authKey = await key.ISO9798SymmetricKey()
 * const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthSymmetric(identity, response, authKey) // -> true
 *
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @param {number} [window=5] - The maximum time difference in seconds
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf auth
 * @async
 * @deprecated
 */
async function VerifyISO97981PassUnilateralAuthSymmetric (
  identity,
  response,
  key,
  window = 5
) {
  const challenge = response.subarray(0, 4)
  const value = response.subarray(4)

  const actual = Math.floor(Date.now() / 1000)
  const observed = challenge.readUInt32BE(0)
  if (Math.abs(actual - observed) > window) return false

  return await VerifyISO97982PassUnilateralAuthSymmetric(
    challenge,
    identity,
    value,
    key
  )
}
module.exports.VerifyISO97981PassUnilateralAuthSymmetric =
  VerifyISO97981PassUnilateralAuthSymmetric

/**
 * Verify ISO 9798-2 Public Key 1-Pass Unilateral Authentication
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 * const identity = Buffer.from('Challenger')
 *
 * // responder: generate response
 * const response = await key.ISO97981PassUnilateralAuthAsymmetric(identity)
 *
 * // verifier: verify response
 * const authKey = await key.ISO9798AsymmetricKey()
 * const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthAsymmetric(identity, response, authKey) // -> true
 *
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @param {number} [window=5] - The maximum time difference in seconds
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf auth
 * @async
 * @deprecated
 */
async function VerifyISO97981PassUnilateralAuthAsymmetric (
  identity,
  response,
  key,
  window = 5
) {
  const challenge = response.subarray(0, 4)
  const value = response.subarray(4)

  const actual = Math.floor(Date.now() / 1000)
  const observed = challenge.readUInt32BE(0)
  if (Math.abs(actual - observed) > window) return false

  return await VerifyISO97982PassUnilateralAuthAsymmetric(
    challenge,
    identity,
    value,
    key
  )
}
module.exports.VerifyISO97981PassUnilateralAuthAsymmetric =
  VerifyISO97981PassUnilateralAuthAsymmetric

/**
 * Verify ISO 9798-2 1-Pass Unilateral Authentication over CCF
 *
 * @example
 * // setup multi-factor derived key
 * const key = await mfkdf.setup.key([ await mfkdf.setup.factors.password('password') ])
 * const identity = Buffer.from('Challenger')
 *
 * // responder: generate response
 * const response = await key.ISO97981PassUnilateralAuthCCF(identity)
 *
 * // verifier: verify response
 * const authKey = await key.ISO9798CCFKey()
 * const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthCCF(identity, response, authKey) // -> true
 *
 * @param {Buffer} identity - The identity of the challenger
 * @param {Buffer} response - The response of the responder
 * @param {Buffer} key - The key used to authenticate
 * @param {number} [window=5] - The maximum time difference in seconds
 * @returns {boolean} Whether the response is valid
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf auth
 * @async
 * @deprecated
 */
async function VerifyISO97981PassUnilateralAuthCCF (
  identity,
  response,
  key,
  window = 5
) {
  const challenge = response.subarray(0, 4)
  const value = response.subarray(4)

  const actual = Math.floor(Date.now() / 1000)
  const observed = challenge.readUInt32BE(0)
  if (Math.abs(actual - observed) > window) return false

  return await VerifyISO97982PassUnilateralAuthCCF(
    challenge,
    identity,
    value,
    key
  )
}
module.exports.VerifyISO97981PassUnilateralAuthCCF =
  VerifyISO97981PassUnilateralAuthCCF

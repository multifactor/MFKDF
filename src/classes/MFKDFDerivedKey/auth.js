/**
 * @file Multi-Factor Derived Key Authentication Functions
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Authentication operations using a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const crypto = require('crypto')

/**
 * ISO 9798-2 2-Pass Unilateral Authentication
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
 * @returns {Buffer} The response value
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function ISO97982PassUnilateralAuthSymmetric (challenge, identity) {
  const plaintext = Buffer.concat([challenge, identity])
  return await this.encrypt(plaintext, 'aes256', 'CBC', true)
}
module.exports.ISO97982PassUnilateralAuthSymmetric = ISO97982PassUnilateralAuthSymmetric

/**
 * ISO 9798-2 Public Key 2-Pass Unilateral Authentication
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
 * @returns {Buffer} The response value
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function ISO97982PassUnilateralAuthAsymmetric (challenge, identity) {
  const plaintext = Buffer.concat([challenge, identity])
  return await this.sign(plaintext, 'rsa1024', true)
}
module.exports.ISO97982PassUnilateralAuthAsymmetric = ISO97982PassUnilateralAuthAsymmetric

/**
 * ISO 9798-2 2-Pass Unilateral Authentication over CCF
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
 * @returns {Buffer} The response value
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function ISO97982PassUnilateralAuthCCF (challenge, identity) {
  const key = await this.getSubkey(32, 'SHA256AUTH', 'sha256')
  const ct = Buffer.concat([challenge, identity, key])
  return crypto.createHash('sha256').update(ct).digest()
}
module.exports.ISO97982PassUnilateralAuthCCF = ISO97982PassUnilateralAuthCCF

/**
 * ISO 9798-2 1-Pass Unilateral Authentication
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
 * @returns {Buffer} The response value
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function ISO97981PassUnilateralAuthSymmetric (identity) {
  const date = Math.floor(Date.now() / 1000)
  const challenge = Buffer.allocUnsafe(4)
  challenge.writeUInt32BE(date, 0)
  const response = await this.ISO97982PassUnilateralAuthSymmetric(challenge, identity)
  return Buffer.concat([challenge, response])
}
module.exports.ISO97981PassUnilateralAuthSymmetric = ISO97981PassUnilateralAuthSymmetric

/**
 * ISO 9798-2 Public Key 1-Pass Unilateral Authentication
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
 * @returns {Buffer} The response value
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function ISO97981PassUnilateralAuthAsymmetric (identity) {
  const date = Math.floor(Date.now() / 1000)
  const challenge = Buffer.allocUnsafe(4)
  challenge.writeUInt32BE(date, 0)
  const response = await this.ISO97982PassUnilateralAuthAsymmetric(challenge, identity)
  return Buffer.concat([challenge, response])
}
module.exports.ISO97981PassUnilateralAuthAsymmetric = ISO97981PassUnilateralAuthAsymmetric

/**
 * ISO 9798-2 1-Pass Unilateral Authentication over CCF
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
 * @returns {Buffer} The response value
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function ISO97981PassUnilateralAuthCCF (identity) {
  const date = Math.floor(Date.now() / 1000)
  const challenge = Buffer.allocUnsafe(4)
  challenge.writeUInt32BE(date, 0)
  const response = await this.ISO97982PassUnilateralAuthCCF(challenge, identity)
  return Buffer.concat([challenge, response])
}
module.exports.ISO97981PassUnilateralAuthCCF = ISO97981PassUnilateralAuthCCF

/**
 * Get the symmetric key used for ISO 9798-2 Unilateral Authentication
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
 * @returns {Buffer} Symmetric key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function ISO9798SymmetricKey () {
  return await this.getSymmetricKey('aes256', true)
}
module.exports.ISO9798SymmetricKey = ISO9798SymmetricKey

/**
 * Get the public key used for ISO 9798-2 Public Key Unilateral Authentication
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
 * @returns {Buffer} Public key (spki-der encoded)
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function ISO9798AsymmetricKey () {
  return (await this.getAsymmetricKeyPair('rsa1024', true)).publicKey
}
module.exports.ISO9798AsymmetricKey = ISO9798AsymmetricKey

/**
 * Get the CCF key used for ISO 9798-2 Unilateral Authentication over CCF
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
 * @returns {Buffer} CCF key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.17.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function ISO9798CCFKey () {
  return await this.getSubkey(32, 'SHA256AUTH', 'sha256')
}
module.exports.ISO9798CCFKey = ISO9798CCFKey

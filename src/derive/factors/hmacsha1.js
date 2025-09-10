/**
 * @file MFKDF HMAC-SHA1 Factor Setup
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Derive an HMAC-SHA1 challenge-response factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const crypto = require('crypto')
const { encrypt, decrypt } = require('../../crypt')

/**
 * Derive a YubiKey-compatible MFKDF HMAC-SHA1 challenge-response factor
 *
 * @example
 * // setup key with hmacsha1 factor
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.hmacsha1()
 * ])
 *
 * // calculate response; could be done using hardware device
 * const secret = setup.outputs.hmacsha1.secret
 * const challenge = Buffer.from(setup.policy.factors[0].params.challenge, 'hex')
 * const response = crypto.createHmac('sha1', secret).update(challenge).digest()
 *
 * // derive key with hmacsha1 factor
 * const derive = await mfkdf.derive.key(setup.policy, {
 *   hmacsha1: mfkdf.derive.factors.hmacsha1(response)
 * })
 *
 * setup.key.toString('hex') // -> 01d0c7236adf2516
 * derive.key.toString('hex') // -> 01d0c7236adf2516
 *
 * @param {Buffer} response - HMAC-SHA1 response
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.21.0
 * @memberof derive.factors
 */
function hmacsha1 (response) {
  if (!Buffer.isBuffer(response)) {
    throw new TypeError('response must be a buffer')
  }

  return async (params) => {
    const oldPaddedKey = Buffer.concat([response, Buffer.alloc(12)])
    const secret = decrypt(Buffer.from(params.pad, 'hex'), oldPaddedKey)

    return {
      type: 'hmacsha1',
      data: secret,
      params: async ({ key }) => {
        const challenge = crypto.randomBytes(64)
        const response = crypto
          .createHmac('sha1', secret.subarray(0, 20))
          .update(challenge)
          .digest()

        const paddedKey = Buffer.concat([response, Buffer.alloc(12)])
        const pad = encrypt(secret, paddedKey)

        return {
          challenge: challenge.toString('hex'),
          pad: pad.toString('hex')
        }
      },
      output: async () => {
        return { secret }
      }
    }
  }
}
module.exports.hmacsha1 = hmacsha1

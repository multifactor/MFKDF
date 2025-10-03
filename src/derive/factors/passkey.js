/**
 * @file MFKDF Passkey Factor Derivation
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Derive passkey factor for multi-factor key derivation
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

/**
 * Derive an MFKDF passkey factor
 *
 * @example
 *  const prf = await crypto.randomBytes(32)
 *
 *  const setup = await mfkdf.setup.key([
 *    await mfkdf.setup.factors.passkey(prf)
 *  ])
 *
 *  const derive = await mfkdf.derive.key(setup.policy, {
 *    passkey: mfkdf.derive.factors.passkey(prf)
 *  })
 *
 *  derive.key.toString('hex').should.equal(setup.key.toString('hex'))
 *
 * @param {Buffer} secret - The 256-bit PRF secret from which to derive an MFKDF factor
 * @returns {function(config:Object): Promise<MFKDFFactor>} Async function to generate MFKDF factor information
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 2.0.0
 * @memberof derive.factors
 */
function passkey(secret) {
  if (!Buffer.isBuffer(secret)) {
    throw new TypeError('secret must be a Buffer')
  }
  if (Buffer.byteLength(secret) !== 32) {
    throw new RangeError('secret must be 32 bytes (256 bits) in length')
  }

  return async () => {
    return {
      type: 'passkey',
      data: secret,
      params: async () => {
        return {}
      },
      output: async () => {
        return {}
      }
    }
  }
}
export { passkey }

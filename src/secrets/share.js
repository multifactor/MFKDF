/**
 * @file Secret Sharing
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Divide a secret into shares using various methods
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const crypto = require('crypto')
const xor = require('buffer-xor')
const secrets = require('secrets.js-34r7h')

/**
   * K-of-N secret sharing. Uses bitwise XOR for k=n, Shamir's Secret Sharing for 1 < K < N, and direct secret sharing for K = 1.
   *
   * @example
   * const shares = await mfkdf.secrets.share(...);
   *
   * @param {Buffer} secret - The secret value to be shared
   * @param {number} k - The threshold of shares required to reconstruct the secret
   * @param {number} n - The number of shares to generate
   * @returns {Array.<Buffer>} An array of N shares as Buffers.
   * @author Vivek Nair (https://nair.me) <vivek@nair.me>
   * @since 0.8.0
   * @memberOf secrets
   */
function share (secret, k, n) {
  if (!Buffer.isBuffer(secret)) throw new TypeError('secret must be a buffer')
  if (secret.length === 0) throw new RangeError('secret must not be empty')
  if (!Number.isInteger(n)) throw new TypeError('n must be an integer')
  if (!(n > 0)) throw new RangeError('n must be positive')
  if (!Number.isInteger(k)) throw new TypeError('k must be an integer')
  if (!(k > 0)) throw new RangeError('k must be positive')
  if (k > n) throw new RangeError('k must be less than or equal to n')

  if (k === 1) { // 1-of-n
    return Array(n).fill(secret)
  } else if (k === n) { // n-of-n
    const shares = []
    let lastShare = Buffer.from(secret)
    for (let i = 1; i < n; i++) {
      const share = crypto.randomBytes(secret.length)
      lastShare = xor(lastShare, share)
      shares.push(share)
    }
    shares.push(lastShare)
    return shares
  } else { // k-of-n
    secrets.init(Math.max(Math.ceil(Math.log(n + 1) / Math.LN2), 3))
    const shares = secrets.share(secret.toString('hex'), n, k, 0)
    return shares.map(share => {
      const components = secrets.extractShareComponents(share)

      if (components.data.length % 2 === 1) components.data = '0' + components.data

      return Buffer.from(components.data, 'hex')
    })
  }
}
module.exports.share = share

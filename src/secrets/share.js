/**
 * @file Secret Sharing
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Divide a secret into shares using various methods
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const sss = require('./library')

/**
 * K-of-N secret sharing. Uses bitwise XOR for k=n, Shamir's Secret Sharing for 1 < K < N, and direct secret sharing for K = 1.
 *
 * @example
 * // share secret using 2-of-3 shares
 * const shares = mfkdf.secrets.share(Buffer.from('abcdefghijklmnopqrst'), 2, 3) // -> [Buffer, Buffer, Buffer]
 *
 * // recover secret using 2 shares
 * const secret = mfkdf.secrets.combine([shares[0], null, shares[2]], 2, 3)
 * secret.toString() // -> hello world
 *
 * // recover original 3 shares
 * const recover = mfkdf.secrets.recover([shares[0], null, shares[2]], 2, 3) // -> [Buffer, Buffer, Buffer]
 *
 * @param {Buffer} secret - The secret value to be shared
 * @param {number} k - The threshold of shares required to reconstruct the secret
 * @param {number} n - The number of shares to generate
 * @returns {Array.<Buffer>} An array of N shares as Buffers
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

  if (k === 1) {
    // 1-of-n
    return Array(n).fill(secret)
  } else {
    // k-of-n
    const shares = sss.split(new Uint8Array(secret), n, k)
    return shares.map((share) => Buffer.from(share))
  }
}
module.exports.share = share

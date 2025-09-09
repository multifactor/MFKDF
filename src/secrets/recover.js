/**
 * @file Secret Recovery
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Recover original shares of a secret from shares using various methods
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const sss = require('./library')

/**
 * K-of-N secret recovery. Uses bitwise XOR for k=n, Shamir's Secret Sharing for 1 < K < N, and direct secret sharing for K = 1.
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
 * @param {Array.<Buffer>} shares - The secret shares to be combined
 * @param {number} k - The threshold of shares required to reconstruct the secret
 * @param {number} n - The number of shares that were originally generated
 * @returns {Buffer} The retrieved secret as a Buffer
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 0.8.0
 * @memberOf secrets
 */
function recover (shares, k, n) {
  if (!Array.isArray(shares)) throw new TypeError('shares must be an array')
  if (shares.length === 0) throw new RangeError('shares must not be empty')
  if (!Number.isInteger(n)) throw new TypeError('n must be an integer')
  if (!(n > 0)) throw new RangeError('n must be positive')
  if (!Number.isInteger(k)) throw new TypeError('k must be an integer')
  if (!(k > 0)) throw new RangeError('k must be positive')
  if (k > n) throw new RangeError('k must be less than or equal to n')
  if (shares.length < k) {
    throw new RangeError('not enough shares provided to retrieve secret')
  }

  if (k === 1) {
    // 1-of-n
    return Array(n).fill(shares.filter((x) => Buffer.isBuffer(x))[0])
  } else {
    // k-of-n
    if (shares.length !== n) {
      throw new RangeError(
        'provide a shares array of size n; use NULL for unknown shares'
      )
    }

    const formatted = []

    for (const [index, share] of shares.entries()) {
      if (share) {
        const id = new Uint8Array([index + 1])
        const value = Buffer.concat([share, id])
        formatted.push(new Uint8Array(value))
      }
    }

    if (formatted.length < k) {
      throw new RangeError('not enough shares provided to retrieve secret')
    }

    const newShares = []

    for (let i = 0; i < n; i++) {
      const newShare = sss.reshare(formatted, i + 1)
      newShares.push(Buffer.from(newShare))
    }

    return newShares
  }
}
module.exports.recover = recover

/**
 * @file Secret Combinig
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Re-combine a secret from shares using various methods
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const xor = require('buffer-xor')
const secrets = require('secrets.js-34r7h')

/**
 * K-of-N secret combining. Uses bitwise XOR for k=n, Shamir's Secret Sharing for 1 < K < N, and direct secret sharing for K = 1.
 *
 * @example
 * // share secret using 2-of-3 shares
 * const shares = mfkdf.secrets.share(Buffer.from('hello world'), 2, 3) // -> [Buffer, Buffer, Buffer]
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
 * @deprecated
 */
function combine (shares, k, n) {
  if (!Array.isArray(shares)) throw new TypeError('shares must be an array')
  if (shares.length === 0) throw new RangeError('shares must not be empty')
  if (!Number.isInteger(n)) throw new TypeError('n must be an integer')
  if (!(n > 0)) throw new RangeError('n must be positive')
  if (!Number.isInteger(k)) throw new TypeError('k must be an integer')
  if (!(k > 0)) throw new RangeError('k must be positive')
  if (k > n) throw new RangeError('k must be less than or equal to n')
  if (shares.length < k) { throw new RangeError('not enough shares provided to retrieve secret') }

  if (k === 1) {
    // 1-of-n
    return shares.filter((x) => Buffer.isBuffer(x))[0]
  } else if (k === n) {
    // n-of-n
    let secret = Buffer.from(shares[0])
    for (let i = 1; i < shares.length; i++) {
      secret = xor(secret, shares[i])
    }
    return secret
  } else {
    // k-of-n
    if (shares.length !== n) {
      throw new RangeError(
        'provide a shares array of size n; use NULL for unknown shares'
      )
    }

    const bits = Math.max(Math.ceil(Math.log(n + 1) / Math.LN2), 3)
    secrets.init(bits)

    const formatted = []

    for (const [index, share] of shares.entries()) {
      if (share) {
        let value = Number(bits).toString(36) // bits
        const maxIdLength = (Math.pow(2, bits) - 1).toString(16).length
        value += (index + 1).toString(16).padStart(maxIdLength, '0') // id
        value += share.toString('hex')
        formatted.push(value)
      }
    }

    if (formatted.length < k) { throw new RangeError('not enough shares provided to retrieve secret') }

    return Buffer.from(secrets.combine(formatted), 'hex')
  }
}
module.exports.combine = combine

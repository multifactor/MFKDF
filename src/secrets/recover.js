/**
 * @file Secret Recovery
 * @copyright Multifactor 2022 All Rights Reserved
 *
 * @description
 * Recover original shares of a secret from shares using various methods
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */
const secrets = require('secrets.js-34r7h')

/**
   * K-of-N secret recovery. Uses bitwise XOR for k=n, Shamir's Secret Sharing for 1 < K < N, and direct secret sharing for K = 1.
   *
   * @example
   * const shares = await mfkdf.secrets.recover(...);
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
  if (shares.length < k) throw new RangeError('not enough shares provided to retrieve secret')

  if (k === 1) { // 1-of-n
    return Array(n).fill(shares.filter(x => Buffer.isBuffer(x))[0])
  } else if (k === n) { // n-of-n
    return shares
  } else { // k-of-n
    if (shares.length !== n) throw new RangeError('provide a shares array of size n; use NULL for unknown shares')

    const bits = Math.max(Math.ceil(Math.log(n + 1) / Math.LN2), 3)
    secrets.init(bits)

    const formatted = []

    for (const [index, share] of shares.entries()) {
      if (share) {
        let value = Number(bits).toString(36) // bits
        const maxIdLength = (Math.pow(2, bits) - 1).toString(16).length
        value += (index + 1).toString(16).padStart(maxIdLength, '0') // id
        let hex = share.toString('hex')
        if (hex.charAt(0) === '0') hex = hex.substring(1)
        value += hex
        formatted.push(value)
      }
    }

    if (formatted.length < k) throw new RangeError('not enough shares provided to retrieve secret')

    const newShares = []

    for (let i = 0; i < n; i++) {
      const newShare = secrets.newShare(i + 1, formatted)
      const components = secrets.extractShareComponents(newShare)
      if (components.data.length % 2 === 1) components.data = '0' + components.data

      newShares.push(Buffer.from(components.data, 'hex'))
    }

    return newShares
  }
}
module.exports.recover = recover

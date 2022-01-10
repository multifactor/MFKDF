/**
 * Key material constructions for specific MFKDF factors
 *
 * @namespace factors
 */

module.exports.factors = {
  ...require('./password'),
  ...require('./questions'),
  ...require('./recoveryCode')
}

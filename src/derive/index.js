/**
 * Multi-factor key derivation
 *
 * @namespace derive
 */
module.exports = {
  ...require('./key'),
  factors: require('./factors')
}

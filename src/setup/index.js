/**
 * Multi-factor derived key setup
 *
 * @namespace setup
 */
module.exports = {
  ...require('./kdf'),
  ...require('./key'),
  factors: require('./factors')
}

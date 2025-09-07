/**
 * Multi-factor derived key setup
 *
 * @namespace setup
 */
module.exports = {
  ...require('./key'),
  factors: require('./factors')
}

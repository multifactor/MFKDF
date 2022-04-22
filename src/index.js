/**
 * @typedef MFKDFFactor
 * @type {object}
 * @property {string} type - Type of factor.
 * @property {string} [id] - Unique identifier of this factor.
 * @property {Buffer} data - Key material for this factor.
 * @property {function} params - Asynchronous function to fetch parameters.
 * @property {function} [output] - Asynchronous function to fetch output.
 */

module.exports = {
  setup: require('./setup'),
  derive: require('./derive'),
  secrets: require('./secrets'),
  policy: require('./policy'),
  auth: require('./auth'),
  ...require('./kdf')
}

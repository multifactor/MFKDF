/**
 * Secrets management
 *
 * @namespace secrets
 */
module.exports = {
  ...require('./share'),
  ...require('./combine'),
  ...require('./recover')
}

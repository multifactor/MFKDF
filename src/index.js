module.exports = {
  ...require('./kdf'),
  ...require('./mfkdf'),
  factors: {
    ...require('./factors/password')
  }
}

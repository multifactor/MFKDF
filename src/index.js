module.exports = {
  ...require('./kdf'),
  ...require('./mfkdf'),
  factors: {
    ...require('./factors/password'),
    ...require('./factors/questions'),
    ...require('./factors/recoveryCode')
  }
}

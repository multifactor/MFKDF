/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('passwordFactor', () => {
  test('type', async () => {
    const passwordFactor = await mfkdf.factors.password('password')
    Buffer.isBuffer(passwordFactor).should.be.true
  })

  test('sha512', async () => {
    const passwordFactor = await mfkdf.factors.password('password', { digest: 'sha512' })
    passwordFactor.toString('hex').should.equal('ae16ce6dfd4a6a0c20421ff80eb3ba4acc13bd1dea45f8bb034b753e4cf2032f')
  })

  test('default/correct', async () => {
    const passwordFactor = await mfkdf.factors.password('password', { salt: 'salt' })
    passwordFactor.toString('hex').should.equal('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
  })

  test('default/equivalent', async () => {
    const passwordFactor = await mfkdf.factors.password('password')
    const kdf = await mfkdf.kdf('password', '', {
      kdf: 'pbkdf2',
      pbkdf2rounds: 1
    })
    passwordFactor.toString('hex').should.equal(kdf.toString('hex'))
  })

  test('default/size', async () => {
    const passwordFactor1 = await mfkdf.factors.password('password')
    passwordFactor1.toString('hex').length.should.equal(64)

    const passwordFactor2 = await mfkdf.factors.password('password', { size: 16 })
    passwordFactor2.toString('hex').length.should.equal(32)

    const passwordFactor3 = await mfkdf.factors.password('password', { size: 32 })
    passwordFactor3.toString('hex').length.should.equal(64)

    const passwordFactor4 = await mfkdf.factors.password('password', { size: 64 })
    passwordFactor4.toString('hex').length.should.equal(128)
  })
})

/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('setup/sharing', () => {
  test('3-of-3', async () => {
    const { key, config } = await mfkdf.setup({
      password1: await mfkdf.factors.password('password1'),
      password2: await mfkdf.factors.password('password2'),
      password3: await mfkdf.factors.password('password3')
    }, 3)
    const key2 = await mfkdf.derive({
      password1: await mfkdf.factors.password('password1'),
      password2: await mfkdf.factors.password('password2'),
      password3: await mfkdf.factors.password('password3')
    }, config)
    key2.toString('hex').should.equal(key.toString('hex'))
    const key3 = await mfkdf.derive({
      password1: await mfkdf.factors.password('password1'),
      password2: await mfkdf.factors.password('password4'),
      password3: await mfkdf.factors.password('password3')
    }, config)
    key3.toString('hex').should.not.equal(key.toString('hex'))
  })
  test('2-of-3', async () => {
    const { key, config } = await mfkdf.setup({
      password1: await mfkdf.factors.password('password1'),
      password2: await mfkdf.factors.password('password2'),
      password3: await mfkdf.factors.password('password3')
    }, 2)
    const key2 = await mfkdf.derive({
      password1: await mfkdf.factors.password('password1'),
      password2: await mfkdf.factors.password('password2'),
      password3: await mfkdf.factors.password('password3')
    }, config)
    key2.toString('hex').should.equal(key.toString('hex'))
    const key3 = await mfkdf.derive({
      password2: await mfkdf.factors.password('password2'),
      password3: await mfkdf.factors.password('password3')
    }, config)
    key3.toString('hex').should.equal(key.toString('hex'))
    const key4 = await mfkdf.derive({
      password1: await mfkdf.factors.password('password1'),
      password3: await mfkdf.factors.password('password3')
    }, config)
    key4.toString('hex').should.equal(key.toString('hex'))
    const key5 = await mfkdf.derive({
      password1: await mfkdf.factors.password('password1'),
      password2: await mfkdf.factors.password('password2')
    }, config)
    key5.toString('hex').should.equal(key.toString('hex'))
    const key6 = await mfkdf.derive({
      password1: await mfkdf.factors.password('password1'),
      password2: await mfkdf.factors.password('password3')
    }, config)
    key6.toString('hex').should.not.equal(key.toString('hex'))
  })
})

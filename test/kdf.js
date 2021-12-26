/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('kdf', () => {
  test('pbkdf2/sha1', async () => {
    const key = await mfkdf.kdf('password', {
      kdf: 'pbkdf2',
      size: 16,
      pbkdf2rounds: 25555,
      pbkdf2digest: 'sha1',
      salt: 'salt'
    })
    key.should.equal('8ee4a527b20aa8feeb78d70447d84e20')
  })

  test('pbkdf2/sha512', async () => {
    const key = await mfkdf.kdf('secret', {
      kdf: 'pbkdf2',
      size: 64,
      pbkdf2rounds: 100000,
      pbkdf2digest: 'sha512',
      salt: 'salt'
    })
    key.should.equal('3745e482c6e0ade35da10139e797157f4a5da669dad7d5da88ef87e47471cc47ed941c7ad618e827304f083f8707f12b7cfdd5f489b782f10cc269e3c08d59ae')
  })

  test('pbkdf2/default', async () => {
    const key1 = await mfkdf.kdf('test', {
      kdf: 'pbkdf2'
    })
    const key2 = await mfkdf.kdf('test', {
      kdf: 'pbkdf2',
      size: 32,
      pbkdf2rounds: 250000,
      pbkdf2digest: 'sha256',
      salt: ''
    })
    key1.should.equal(key2)
  })
})

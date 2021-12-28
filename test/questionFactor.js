/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('passwordFactor', () => {
  test('example', async () => {
    const questionFactor = await mfkdf.factors.questions({
      'first-pet': 'max',
      'birth-city': 'jacksonville',
      'mother-maiden-name': 'smith'
    }, {
      size: 16,
      digest: 'sha512'
    })
    questionFactor.toString('hex').should.equal('51fd94bc53fb8d1a9c1ca3bc1199a01b')
  })
  test('format', async () => {
    const questionFactor = await mfkdf.factors.questions({
      'first-pet': 'max',
      'birth-city': 'jacksonville',
      'mother-maiden-name': 'smith'
    })
    const passwordFactor = await mfkdf.factors.password('birth-city:jacksonville;first-pet:max;mother-maiden-name:smith')
    questionFactor.toString('hex').should.equal(passwordFactor.toString('hex'))
  })
  test('normalization', async () => {
    const questionFactor1 = await mfkdf.factors.questions({
      'first-pet': 'max',
      'birth-city': 'jacksonville',
      'mothers-maiden-name': 'smith'
    })
    const questionFactor2 = await mfkdf.factors.questions({
      'Birth-City': 'Jacksonville',
      'First-Pet': 'Max',
      'Mother\'s-Maiden-Name': 'Smith'
    }, { normalize: true })
    questionFactor1.toString('hex').should.equal(questionFactor2.toString('hex'))
    const questionFactor3 = await mfkdf.factors.questions({
      'Birth-City': 'Jacksonville',
      'First-Pet': 'Max',
      'Mother\'s-Maiden-Name': 'Smith'
    }, { normalize: false })
    questionFactor1.toString('hex').should.not.equal(questionFactor3.toString('hex'))
  })
  test('correctness', async () => {
    const questionFactor = await mfkdf.factors.questions({
      'first-pet': 'max',
      'birth-city': 'jacksonville',
      'mother-maiden-name': 'smith'
    }, { digest: 'sha1' })
    questionFactor.toString('hex').should.equal('ec3c791aabee716f806c3231b71a929f1a26baca9a827f5e930012dcd002fada')
  })
})

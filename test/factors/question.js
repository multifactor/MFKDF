/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('factors/question', () => {
  test('valid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.question(' Fido-', { question: 'What is the name of your first pet?' })
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      question: mfkdf.derive.factors.question('-f_i%d#o ? ')
    })

    setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive.policy))
  })

  test('invalid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.question('Fido', { question: 'What is the name of your first pet?' })
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      question: mfkdf.derive.factors.question('Rex')
    })

    setup.key.toString('hex').should.not.equal(derive.key.toString('hex'))
  })

  suite('errors', () => {
    test('derive', () => {
      (() => {
        mfkdf.derive.factors.question(123)
      }).should.throw(TypeError);

      (() => {
        mfkdf.derive.factors.question('')
      }).should.throw(RangeError)
    })

    test('setup', () => {
      mfkdf.setup.factors.question(12345).should.be.rejectedWith(TypeError)
      mfkdf.setup.factors.question('').should.be.rejectedWith(RangeError)
      mfkdf.setup.factors.question('hello', { id: 12345 }).should.be.rejectedWith(TypeError)
      mfkdf.setup.factors.question('hello', { id: '' }).should.be.rejectedWith(RangeError)
      mfkdf.setup.factors.question('hello', { question: 12345 }).should.be.rejectedWith(TypeError)
    })
  })
})

/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('mfkdf2/mfdpg2', () => {
  suite('basics', () => {
    test('portability', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])
      const password = await setup.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )
      password.length.should.be.above(5)
      password.length.should.be.below(11);
      /[a-zA-Z]{6,10}/.test(password).should.be.true
      const password2 = await setup.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )
      password.should.equal(password2)

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })
      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
      const password3 = await derive.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )
      password.should.equal(password3)
    })

    test('full-example', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])
      const policy = /([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*/
      const password1 = await setup.derivePassword(
        'example.com',
        'salt',
        policy
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })
      const password3 = await derive.derivePassword(
        'example.com',
        'salt',
        policy
      )
      password1.should.equal(password3)
    })
  })

  suite('correctness', () => {
    test('basic-test', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])
      const password1 = await setup.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )
      const password2 = await setup.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )
      password1.should.equal(password2)
    })

    test('full-test', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])
      const password1 = await setup.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })
      const password2 = await derive.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )

      password1.should.equal(password2)
    })
  })

  suite('safety', () => {
    test('basic-test', async () => {
      const setup1 = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])
      const setup2 = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])
      const password1 = await setup1.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )
      const password2 = await setup2.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )
      password1.should.not.equal(password2)
    })

    test('full-test', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])
      const password1 = await setup.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })
      const password2 = await derive.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )

      password1.should.equal(password2)

      const derive2 = await mfkdf.derive.key(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password2')
        },
        false
      )
      const password3 = await derive2.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )
      password1.should.not.equal(password3)
    })
  })

  suite('compatibility', () => {
    test('basic-policy', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])
      const password = await setup.derivePassword(
        'example.com',
        'salt',
        /[a-zA-Z]{6,10}/
      )
      password.length.should.be.above(5)
      password.length.should.be.below(11)
    })

    test('custom-policy', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])
      const regex = /([A-Za-z]+[0-9]|[0-9]+[A-Za-z])[A-Za-z0-9]*/
      const password = await setup.derivePassword('example.com', 'salt', regex)
      regex.test(password).should.be.true
    })
  })
})

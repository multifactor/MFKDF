/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('policy', () => {
  suite('validate', () => {
    test('valid', async () => {
      const policy = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      )

      mfkdf.policy.validate(policy.policy).should.be.true
    })

    test('invalid', async () => {
      mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password3', { id: 'password1' }),
            await mfkdf.setup.factors.password('password4', { id: 'password2' })
          )
        )
      ).should.be.rejectedWith(RangeError)
    })
  })

  suite('evaluate', () => {
    test('basic 1', async () => {
      const policy = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      )

      mfkdf.policy.evaluate(policy.policy, ['password1', 'password2']).should.be.false
      mfkdf.policy.evaluate(policy.policy, ['password3', 'password4']).should.be.false
      mfkdf.policy.evaluate(policy.policy, ['password1', 'password4']).should.be.true
      mfkdf.policy.evaluate(policy.policy, ['password2', 'password3']).should.be.true
    })

    test('basic 2', async () => {
      const policy = await mfkdf.policy.setup(
        await mfkdf.policy.or(
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      )

      mfkdf.policy.evaluate(policy.policy, ['password1', 'password2']).should.be.true
      mfkdf.policy.evaluate(policy.policy, ['password3', 'password4']).should.be.true
      mfkdf.policy.evaluate(policy.policy, ['password1', 'password4']).should.be.false
      mfkdf.policy.evaluate(policy.policy, ['password2', 'password3']).should.be.false
    })
  })

  suite('derive', async () => {
    test('all', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.all([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ])
      )

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2'),
        password3: mfkdf.derive.factors.password('password3'),
        password4: mfkdf.derive.factors.password('password4')
      })
      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('any', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.any([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ])
      )

      const derive = await mfkdf.policy.derive(setup.policy, {
        password3: mfkdf.derive.factors.password('password3')
      })
      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('atLeast', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.atLeast(3, [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' }),
          await mfkdf.setup.factors.password('password4', { id: 'password4' })
        ])
      )

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2'),
        password4: mfkdf.derive.factors.password('password4')
      })
      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('basic 1', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      )

      const derive1 = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password3: mfkdf.derive.factors.password('password3')
      })
      derive1.key.toString('hex').should.equal(setup.key.toString('hex'))

      const derive2 = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password4: mfkdf.derive.factors.password('password4')
      })
      derive2.key.toString('hex').should.equal(setup.key.toString('hex'))

      const derive3 = await mfkdf.policy.derive(setup.policy, {
        password2: mfkdf.derive.factors.password('password2'),
        password3: mfkdf.derive.factors.password('password3')
      })
      derive3.key.toString('hex').should.equal(setup.key.toString('hex'))

      const derive4 = await mfkdf.policy.derive(setup.policy, {
        password2: mfkdf.derive.factors.password('password2'),
        password4: mfkdf.derive.factors.password('password4')
      })
      derive4.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('basic 2', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.or(
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password('password1', { id: 'password1' }),
            await mfkdf.setup.factors.password('password2', { id: 'password2' })
          ),
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password('password3', { id: 'password3' }),
            await mfkdf.setup.factors.password('password4', { id: 'password4' })
          )
        )
      )

      const derive1 = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })
      derive1.key.toString('hex').should.equal(setup.key.toString('hex'))

      const derive2 = await mfkdf.policy.derive(setup.policy, {
        password3: mfkdf.derive.factors.password('password3'),
        password4: mfkdf.derive.factors.password('password4')
      })
      derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('deep', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.policy.and(
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password('password2', { id: 'password2' }),
              await mfkdf.setup.factors.password('password3', { id: 'password3' })
            ),
            await mfkdf.policy.and(
              await mfkdf.setup.factors.password('password4', { id: 'password4' }),
              await mfkdf.policy.or(
                await mfkdf.setup.factors.password('password5', { id: 'password5' }),
                await mfkdf.setup.factors.password('password6', { id: 'password6' })
              )
            )
          )
        )
      )

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2'),
        password4: mfkdf.derive.factors.password('password4'),
        password6: mfkdf.derive.factors.password('password6')
      })
      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })
  })

  suite('errors', () => {
    test('invalid policy', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.policy.and(
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password('password1', { id: 'password1' }),
              await mfkdf.setup.factors.password('password2', { id: 'password2' })
            ),
            await mfkdf.policy.and(
              await mfkdf.setup.factors.password('password4', { id: 'password4' }),
              await mfkdf.policy.or(
                await mfkdf.setup.factors.password('password5', { id: 'password5' }),
                await mfkdf.setup.factors.password('password6', { id: 'password6' })
              )
            )
          )
        )
      ])

      mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2'),
        password4: mfkdf.derive.factors.password('password4'),
        password6: mfkdf.derive.factors.password('password6')
      }).should.be.rejectedWith(TypeError)
    })

    test('invalid factors', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.policy.and(
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password('password2', { id: 'password2' }),
              await mfkdf.setup.factors.password('password3', { id: 'password3' })
            ),
            await mfkdf.policy.and(
              await mfkdf.setup.factors.password('password4', { id: 'password4' }),
              await mfkdf.policy.or(
                await mfkdf.setup.factors.password('password5', { id: 'password5' }),
                await mfkdf.setup.factors.password('password6', { id: 'password6' })
              )
            )
          )
        )
      )

      mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2'),
        password4: mfkdf.derive.factors.password('password4')
      }).should.be.rejectedWith(RangeError)
    })
  })
})

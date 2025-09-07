/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('setup/kdf', () => {
  suite('hkdf', () => {
    test('defaults', async () => {
      mfkdf.setup
        .kdf({
          kdf: 'hkdf'
        })
        .should.deep.equal({
          type: 'hkdf',
          params: {
            digest: 'sha256'
          }
        })
    })

    suite('hkdfdigest', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'hkdf',
            hkdfdigest: 0
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'hkdf',
            hkdfdigest: 'foo'
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup
          .kdf({
            kdf: 'hkdf',
            hkdfdigest: 'sha512'
          })
          .should.deep.equal({
            type: 'hkdf',
            params: {
              digest: 'sha512'
            }
          })
      })
    })
  })

  suite('argon2', async () => {
    test('defaults', async () => {
      mfkdf.setup.kdf({}).should.deep.equal({
        type: 'argon2id',
        params: {
          rounds: 2,
          memory: 24576,
          parallelism: 1
        }
      })
    })

    suite('argon2time', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'argon2id',
            argon2time: 'foo'
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'argon2id',
            argon2time: 0
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup
          .kdf({
            kdf: 'argon2d',
            argon2time: 10
          })
          .should.deep.equal({
            type: 'argon2d',
            params: {
              rounds: 10,
              memory: 24576,
              parallelism: 1
            }
          })
      })
    })

    suite('argon2mem', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'argon2id',
            argon2mem: 'foo'
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'argon2id',
            argon2mem: 0
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup
          .kdf({
            kdf: 'argon2i',
            argon2mem: 12345
          })
          .should.deep.equal({
            type: 'argon2i',
            params: {
              rounds: 2,
              memory: 12345,
              parallelism: 1
            }
          })
      })
    })

    suite('argon2parallelism', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'argon2id',
            argon2parallelism: 'foo'
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'argon2id',
            argon2parallelism: 0
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup
          .kdf({
            kdf: 'argon2id',
            argon2parallelism: 2
          })
          .should.deep.equal({
            type: 'argon2id',
            params: {
              rounds: 2,
              memory: 24576,
              parallelism: 2
            }
          })
      })
    })

    test('kdf/type', async () => {
      (() => {
        mfkdf.setup.kdf({
          kdf: 123
        })
      }).should.throw(TypeError)
    })

    test('kdf/range', async () => {
      (() => {
        mfkdf.setup.kdf({
          kdf: 'foo'
        })
      }).should.throw(RangeError)
    })
  })
})

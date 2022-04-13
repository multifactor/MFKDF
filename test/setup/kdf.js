/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('setup/kdf', () => {
  suite('pbkdf2', () => {
    test('defaults', async () => {
      mfkdf.setup.kdf({
        kdf: 'pbkdf2'
      }).should.deep.equal({
        type: 'pbkdf2',
        params: {
          rounds: 310000,
          digest: 'sha256'
        }
      })
    })

    suite('pbkdf2rounds', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'pbkdf2',
            pbkdf2rounds: 'foo'
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'pbkdf2',
            pbkdf2rounds: 0
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup.kdf({
          kdf: 'pbkdf2',
          pbkdf2rounds: 100000
        }).should.deep.equal({
          type: 'pbkdf2',
          params: {
            rounds: 100000,
            digest: 'sha256'
          }
        })
      })
    })

    suite('pbkdf2digest', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'pbkdf2',
            pbkdf2digest: 0
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'pbkdf2',
            pbkdf2digest: 'foo'
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup.kdf({
          kdf: 'pbkdf2',
          pbkdf2digest: 'sha512'
        }).should.deep.equal({
          type: 'pbkdf2',
          params: {
            rounds: 310000,
            digest: 'sha512'
          }
        })
      })
    })
  })

  suite('bcrypt', async () => {
    test('defaults', async () => {
      mfkdf.setup.kdf({
        kdf: 'bcrypt'
      }).should.deep.equal({
        type: 'bcrypt',
        params: {
          rounds: 10
        }
      })
    })

    suite('bcryptrounds', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'bcrypt',
            bcryptrounds: 'foo'
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'bcrypt',
            bcryptrounds: 0
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup.kdf({
          kdf: 'bcrypt',
          bcryptrounds: 25
        }).should.deep.equal({
          type: 'bcrypt',
          params: {
            rounds: 25
          }
        })
      })
    })
  })

  suite('scrypt', async () => {
    test('defaults', async () => {
      mfkdf.setup.kdf({
        kdf: 'scrypt'
      }).should.deep.equal({
        type: 'scrypt',
        params: {
          rounds: 16384,
          blocksize: 8,
          parallelism: 1
        }
      })
    })

    suite('scryptcost', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'scrypt',
            scryptcost: 'foo'
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'scrypt',
            scryptcost: 0
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup.kdf({
          kdf: 'scrypt',
          scryptcost: 12345
        }).should.deep.equal({
          type: 'scrypt',
          params: {
            rounds: 12345,
            blocksize: 8,
            parallelism: 1
          }
        })
      })
    })

    suite('scryptblocksize', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'scrypt',
            scryptblocksize: 'foo'
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'scrypt',
            scryptblocksize: 0
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup.kdf({
          kdf: 'scrypt',
          scryptblocksize: 24
        }).should.deep.equal({
          type: 'scrypt',
          params: {
            rounds: 16384,
            blocksize: 24,
            parallelism: 1
          }
        })
      })
    })

    suite('scryptparallelism', async () => {
      test('invalid/type', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'scrypt',
            scryptparallelism: 'foo'
          })
        }).should.throw(TypeError)
      })

      test('invalid/range', async () => {
        (() => {
          mfkdf.setup.kdf({
            kdf: 'scrypt',
            scryptparallelism: 0
          })
        }).should.throw(RangeError)
      })

      test('valid', async () => {
        mfkdf.setup.kdf({
          kdf: 'scrypt',
          scryptparallelism: 2
        }).should.deep.equal({
          type: 'scrypt',
          params: {
            rounds: 16384,
            blocksize: 8,
            parallelism: 2
          }
        })
      })
    })
  })

  suite('argon2', async () => {
    test('defaults', async () => {
      mfkdf.setup.kdf({
      }).should.deep.equal({
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
        mfkdf.setup.kdf({
          kdf: 'argon2d',
          argon2time: 10
        }).should.deep.equal({
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
        mfkdf.setup.kdf({
          kdf: 'argon2i',
          argon2mem: 12345
        }).should.deep.equal({
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
        mfkdf.setup.kdf({
          kdf: 'argon2id',
          argon2parallelism: 2
        }).should.deep.equal({
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

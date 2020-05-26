import errors from '../src/errors'
import mock from './utils/mock'
import { CryptoSystem, KeyUse } from '../src/types'

describe('errors', () => {

  describe('checkIsKeyPair', () => {
    it('throws on null', () => {
      expect(() => {
        errors.checkIsKeyPair(null)
      }).toThrow(errors.KeyDoesNotExist)
    })

    it('throws on a symm key', () => {
      expect(() => {
        errors.checkIsKeyPair(mock.symmKey)
      }).toThrow(errors.NotKeyPair)
    })

    it('returns on valid keyapir', () => {
      const resp = errors.checkIsKeyPair(mock.keys)
      expect(resp).toEqual(mock.keys)
    })
  })


  describe('checkIsKey', () => {
    it('throws on null', () => {
      expect(() => {
        errors.checkIsKey(null)
      }).toThrow(errors.KeyDoesNotExist)
    })

    it('throws on a symm key', () => {
      expect(() => {
        errors.checkIsKey(mock.keys)
      }).toThrow(errors.NotKey)
    })

    it('returns on valid keyapir', () => {
      const resp = errors.checkIsKey(mock.symmKey)
      expect(resp).toEqual(mock.symmKey)
    })
  })


  describe('checkValidCryptoSystem', () => {
    it('throws on bad input', () => {
      expect(() => {
        errors.checkValidCryptoSystem("nonsense" as any)
      }).toThrow(errors.UnsupportedCrypto)
    })

    describe('passes on valid inputs', () => {
      [CryptoSystem.ECC, CryptoSystem.RSA].map((val: CryptoSystem) => {
        it(`passes on ${val}`, () => {
          errors.checkValidCryptoSystem(val)
          expect(true)
        })
      })
    })
  })


  describe('checkValidKeyUse', () => {
    it('throws on bad input', () => {
      expect(() => {
        errors.checkValidKeyUse("nonsense" as any)
      }).toThrow(errors.InvalidKeyUse)
    })

    describe('passes on valid inputs', () => {
      [KeyUse.Read, KeyUse.Write].map((val: KeyUse) => {
        it(`passes on ${val}`, () => {
          errors.checkValidKeyUse(val)
          expect(true)
        })
      })
    })
  })
})

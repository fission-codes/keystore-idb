import { webcrypto } from 'one-webcrypto'
import config from '../src/config'
import { CryptoSystem, SymmAlg, SymmKeyLength } from '../src/types'
import utils from '../src/utils'
import { mock } from './utils'

describe('config', () => {
  describe('eccEnabled', () => {

    describe('structural clone works', () => {
      let fakeClone: jest.SpyInstance
      let fakeMake: jest.Mock
      let response: boolean

      beforeAll(async () => {
        fakeClone = jest.spyOn(utils, 'structuralClone')
        fakeClone.mockResolvedValue(undefined)

        fakeMake = jest.fn(() => new Promise(r => r(mock.keys)))
        webcrypto.subtle.generateKey = fakeMake

        response = await config.eccEnabled()
      })

      it('calls structural clone once', () => {
        expect(fakeClone).toBeCalledTimes(1)
      })

      it('returns true', () => {
        expect(response).toEqual(true)
      })
    })

    describe('structural clone does not works', () => {
      let fakeClone: jest.SpyInstance
      let fakeMake: jest.Mock
      let response: boolean

      beforeAll(async () => {
        fakeClone = jest.spyOn(utils, 'structuralClone')
        fakeClone.mockReturnValue(
          new Promise((_resp, rej) => rej(new Error("cannot structural clone")))
        )

        fakeMake = jest.fn(() => new Promise(r => r(mock.keys)))
        webcrypto.subtle.generateKey = fakeMake

        response = await config.eccEnabled()
      })

      it('calls structural clone once', () => {
        expect(fakeClone).toBeCalledTimes(1)
      })

      it('returns false', () => {
        expect(response).toEqual(false)
      })
    })
  })


  describe('normalize', () => {
    it('defaults to defaultConfig', () => {
      const cfg = config.normalize()
      expect(cfg).toEqual(config.defaultConfig)
    })

    it('merges with default config', () => {
      const cfg = config.normalize({
        exchangeKeyPairName: 'test'
      })
      const modifiedDef = {
        ...config.defaultConfig,
        exchangeKeyPairName: 'test'
      }
      expect(cfg).toEqual(modifiedDef)
    })

  describe('merge', () => {
    it('it correctly merges configs', () => {
      const merged = config.merge(config.defaultConfig, { symmAlg: SymmAlg.AES_GCM, symmKeyLength: SymmKeyLength.B512 })
      expect(merged).toEqual({
        ...config.defaultConfig,
        symmAlg: SymmAlg.AES_GCM,
        symmLen: SymmKeyLength.B512
      })
    })

    it('it works when an empty overwrite is passed', () => {
      const merged = config.merge(config.defaultConfig)
      expect(merged).toEqual(config.defaultConfig)
    })
  })
})

})

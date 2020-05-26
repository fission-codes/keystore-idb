import KeyStore from '../src'
import ECCKeyStore from '../src/ecc/keystore'
import RSAKeyStore from '../src/rsa/keystore'
import config from '../src/config'
import errors from '../src/errors'
import { CryptoSystem } from '../src/types'
import IDB from '../src/idb'

jest.mock('../src/idb')

describe('keystore', () => {
  describe('init', () => {
    describe('ecc enabled', () => {

      beforeEach(async () => {
        const mock = jest.spyOn(config, 'eccEnabled')
        mock.mockResolvedValue(true)
      })

      it('should instantiate an ecc keystore if not specified', async () => {
        const resp = await KeyStore.init()
        const eccKeystore = await ECCKeyStore.init()
        expect(resp).toStrictEqual(eccKeystore)
      })

      it('should instantiate an rsa keystore if specified', async () => {
        const resp = await KeyStore.init({ type: CryptoSystem.RSA })
        const rsaKeystore = await RSAKeyStore.init()
        expect(resp).toStrictEqual(rsaKeystore)
      })
    })

    describe('ecc not enabled', () => {

      beforeEach(async () => {
        jest.spyOn(config, 'eccEnabled').mockResolvedValue(false)
      })

      it('should instantiate an rsa keystore if not specified', async () => {
        const resp = await KeyStore.init()
        const rsaKeystore = await RSAKeyStore.init()
        expect(resp).toStrictEqual(rsaKeystore)
      })

      it('should throw an error if ecc is specified', async () => {
        let error
        try{
          await KeyStore.init({ type: CryptoSystem.ECC })
        }catch(err){
          error = err
        }
        expect(error).toEqual(errors.ECCNotEnabled)
      })

      it('should throw an error if an unsupported type of crypto is specified', async () => {
        let error
        try{
          await KeyStore.init({ type: 'some-other-crypto' as any })
        }catch(err){
          error = err
        }
        expect(error).toEqual(errors.UnsupportedCrypto)
      })

    })
  })

  describe('clear', () => {
    let mock: jest.SpyInstance

    beforeAll(async () => {
      mock = jest.spyOn(IDB, 'clear')
      await KeyStore.clear()
    })

    it('calls IDB.clear once', () => {
      expect(mock).toBeCalledTimes(1)
    })
  })
})

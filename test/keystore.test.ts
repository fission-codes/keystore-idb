import KeyStore from '../src/keystore'
import keys from '../src/ecc/keys'
import operations from '../src/ecc/operations'
import config, { defaultConfig } from '../src/config'
import idb from '../src/idb'
import { DEFAULT_CHAR_SIZE, DEFAULT_ECC_CURVE, DEFAULT_HASH_ALG } from '../src/constants'
import { EccCurve, KeyUse, CryptoSystem } from '../src/types'
import { mock, keystoreMethod } from './utils'

jest.mock('../src/idb')
jest.mock('../src/ecc/keys')

describe("KeyStore", () => {
  describe("init", () => {

    let response: any
    let fakeStore: jest.SpyInstance
    let fakeGen: jest.SpyInstance
    let fakeCreateifDNE: jest.SpyInstance
    let fakeEccEnabled: jest.SpyInstance

    beforeAll(async () => {
      fakeStore = jest.spyOn(idb, 'createStore')
      fakeStore.mockReturnValue(mock.idbStore)

      fakeGen = jest.spyOn(keys, 'genKeyPair')
      fakeGen.mockReturnValue(mock.keys)

      fakeEccEnabled = jest.spyOn(config, 'eccEnabled')
      fakeEccEnabled.mockResolvedValue(true)

      fakeCreateifDNE = jest.spyOn(idb, 'createIfDoesNotExist')
      fakeCreateifDNE.mockImplementation((_name, makeFn, _store) => {
        makeFn()
      })

      response = await KeyStore.init({ exchangeKeyPairName: 'test-exchange', writeKeyPairName: 'test-write' })
      await response.genExchangeKeyPair()
      await response.genWriteKeyPair()
      
    })

    it('should initialize a keystore with expected params', () => {
      let cfg = config.normalize({
        exchangeKeyPairName: 'test-exchange',
        writeKeyPairName: 'test-write'
      })
      const keystore = new KeyStore(cfg, mock.idbStore)
      expect(response).toStrictEqual(keystore)
    })

    it('should call createIfDoesNotExist with correct params (exchange key)', () => {
      expect(fakeCreateifDNE.mock.calls[0][0]).toEqual('test-exchange')
      expect(fakeCreateifDNE.mock.calls[0][2]).toEqual(mock.idbStore)
    })

    it('should call createIfDoesNotExist with correct params (write key)', () => {
      expect(fakeCreateifDNE.mock.calls[1][0]).toEqual('test-write')
      expect(fakeCreateifDNE.mock.calls[1][2]).toEqual(mock.idbStore)
    })

    it('should call genKeyPair with correct params (exchange key)', () => {
      expect(fakeGen.mock.calls[0]).toEqual([
        EccCurve.P_384,
        KeyUse.Exchange
      ])
    })

    it('should call genKeyPair with correct params (write key)', () => {
      expect(fakeGen.mock.calls[1]).toEqual([
        EccCurve.P_384,
        KeyUse.Write
      ])
    })

  })

  // Note: These don't work because the mocks are not correct
  // keystoreMethod({
  //   desc: 'sign',
  //   mocks: [
  //     {
  //       mod: operations,
  //       meth: 'sign',
  //       resp: mock.sigBytes,
  //       params: [
  //         mock.msgStr,
  //         mock.writeKeys.privateKey as CryptoKey,
  //         DEFAULT_CHAR_SIZE,
  //         DEFAULT_HASH_ALG
  //       ]
  //     }
  //   ],
  //   reqFn: (ks) => ks.sign(mock.msgStr),
  //   expectedResp: mock.sigStr,
  // })


  // keystoreMethod({
  //   desc: 'verify',
  //   mocks: [
  //     {
  //       mod: operations,
  //       meth: 'verify',
  //       resp: true,
  //       params: [
  //         mock.msgStr,
  //         mock.sigStr,
  //         mock.keyBase64,
  //         DEFAULT_CHAR_SIZE,
  //         DEFAULT_ECC_CURVE,
  //         DEFAULT_HASH_ALG
  //       ]
  //     }
  //   ],
  //   reqFn: (ks) => ks.verify(mock.msgStr, mock.sigStr, mock.keyBase64),
  //   expectedResp: true,
  // })


  // keystoreMethod({
  //   desc: 'encrypt',
  //   mocks: [
  //     {
  //       mod: operations,
  //       meth: 'encrypt',
  //       resp: mock.cipherBytes,
  //       params: [
  //         mock.msgStr,
  //         mock.keys.privateKey,
  //         mock.keyBase64,
  //         DEFAULT_CHAR_SIZE,
  //         DEFAULT_ECC_CURVE
  //       ]
  //     }
  //   ],
  //   reqFn: (ks) => ks.encrypt(mock.msgStr, mock.keyBase64),
  //   expectedResp: mock.cipherStr,
  // })


  // keystoreMethod({
  //   desc: 'decrypt',
  //   mocks: [
  //     {
  //       mod: operations,
  //       meth: 'decrypt',
  //       resp: mock.msgBytes,
  //       params: [
  //         mock.cipherStr,
  //         mock.keys.privateKey,
  //         mock.keyBase64,
  //         DEFAULT_ECC_CURVE
  //       ]
  //     }
  //   ],
  //   reqFn: (ks) => ks.decrypt(mock.cipherStr, mock.keyBase64),
  //   expectedResp: mock.msgStr,
  // })
})

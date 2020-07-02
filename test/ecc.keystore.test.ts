import ECCKeyStore from '../src/ecc/keystore'
import keys from '../src/ecc/keys'
import operations from '../src/ecc/operations'
import config, { defaultConfig } from '../src/config'
import idb from '../src/idb'
import { DEFAULT_CHAR_SIZE, DEFAULT_ECC_CURVE, DEFAULT_HASH_ALG } from '../src/constants'
import { EccCurve, KeyUse, CryptoSystem } from '../src/types'
import { mock, keystoreMethod } from './utils'

jest.mock('../src/idb')

describe("ECCKeyStore", () => {
  describe("init", () => {

    let response: any
    let fakeStore: jest.SpyInstance
    let fakeMake: jest.SpyInstance
    let fakeCreateifDNE: jest.SpyInstance

    beforeAll(async () => {
      fakeStore = jest.spyOn(idb, 'createStore')
      fakeStore.mockReturnValue(mock.idbStore)

      fakeMake = jest.spyOn(keys, 'makeKeypair')
      fakeMake.mockResolvedValue(mock.keys)

      fakeCreateifDNE = jest.spyOn(idb, 'createIfDoesNotExist')
      fakeCreateifDNE.mockImplementation((_name, makeFn) => {
        makeFn()
      })

      response = await ECCKeyStore.init({ readKeyName: 'test-read', writeKeyName: 'test-write' })
    })

    it('should initialize a keystore with expected params', () => {
      let cfg = config.normalize({
        type: CryptoSystem.ECC,
        readKeyName: 'test-read',
        writeKeyName: 'test-write'
      })
      const keystore = new ECCKeyStore(cfg, mock.idbStore)
      expect(response).toStrictEqual(keystore)
    })

    it('should call createIfDoesNotExist with correct params (read key)', () => {
      expect(fakeCreateifDNE.mock.calls[0][0]).toEqual('test-read')
      expect(fakeCreateifDNE.mock.calls[0][2]).toEqual(mock.idbStore)
    })

    it('should call createIfDoesNotExist with correct params (write key)', () => {
      expect(fakeCreateifDNE.mock.calls[1][0]).toEqual('test-write')
      expect(fakeCreateifDNE.mock.calls[1][2]).toEqual(mock.idbStore)
    })

    it('should call makeKeypair with correct params (read key)', () => {
      expect(fakeMake.mock.calls[0]).toEqual([
        EccCurve.P_256,
        KeyUse.Read
      ])
    })

    it('should call makeKeypair with correct params (write key)', () => {
      expect(fakeMake.mock.calls[1]).toEqual([
        EccCurve.P_256,
        KeyUse.Write
      ])
    })

  })


  keystoreMethod({
    desc: 'sign',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'sign',
        resp: mock.sigBytes,
        params: [
          mock.msgStr,
          mock.writeKeys.privateKey,
          DEFAULT_CHAR_SIZE,
          DEFAULT_HASH_ALG
        ]
      }
    ],
    reqFn: (ks) => ks.sign(mock.msgStr),
    expectedResp: mock.sigStr,
  })


  keystoreMethod({
    desc: 'verify',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'verify',
        resp: true,
        params: [
          mock.msgStr,
          mock.sigStr,
          mock.keyBase64,
          DEFAULT_CHAR_SIZE,
          DEFAULT_ECC_CURVE,
          DEFAULT_HASH_ALG
        ]
      }
    ],
    reqFn: (ks) => ks.verify(mock.msgStr, mock.sigStr, mock.keyBase64),
    expectedResp: true,
  })


  keystoreMethod({
    desc: 'encrypt',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'encrypt',
        resp: mock.cipherBytes,
        params: [
          mock.msgStr,
          mock.keys.privateKey,
          mock.keyBase64,
          DEFAULT_CHAR_SIZE,
          DEFAULT_ECC_CURVE
        ]
      }
    ],
    reqFn: (ks) => ks.encrypt(mock.msgStr, mock.keyBase64),
    expectedResp: mock.cipherStr,
  })


  keystoreMethod({
    desc: 'decrypt',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'decrypt',
        resp: mock.msgBytes,
        params: [
          mock.cipherStr,
          mock.keys.privateKey,
          mock.keyBase64,
          DEFAULT_CHAR_SIZE,
          DEFAULT_ECC_CURVE
        ]
      }
    ],
    reqFn: (ks) => ks.decrypt(mock.cipherStr, mock.keyBase64),
    expectedResp: mock.msgStr,
  })


  keystoreMethod({
    desc: 'publicReadKey',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'getPublicKey',
        resp: mock.keyBase64,
        params: [
          mock.keys
        ]
      }
    ],
    reqFn: (ks) => ks.publicReadKey(),
    expectedResp: mock.keyBase64,
  })


  keystoreMethod({
    desc: 'publicWriteKey',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'getPublicKey',
        resp: mock.keyBase64,
        params: [
          mock.writeKeys
        ]
      }
    ],
    reqFn: (ks) => ks.publicWriteKey(),
    expectedResp: mock.keyBase64,
  })

})

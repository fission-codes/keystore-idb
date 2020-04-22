import ECCKeyStore from '../src/ecc/keystore'
import keys from '../src/ecc/keys'
import operations from '../src/ecc/operations'
import config from '../src/config'
import idb from '../src/idb'
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
        meth: 'signBytes', 
        resp: mock.sigBytes,
        params: [
          mock.msgBytes,
          mock.writeKeys.privateKey,
          config.defaultConfig.hashAlg
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
        meth: 'verifyBytes', 
        resp: true,
        params: [
          mock.msgBytes,
          mock.sigBytes,
          mock.writeKeys.publicKey,
          config.defaultConfig.hashAlg
        ]
      },
      {
        mod: keys,
        meth: 'importPublicKey',
        resp: mock.writeKeys.publicKey,
        params: [
          mock.keyBase64,
          config.defaultConfig.curve,
          KeyUse.Write
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
        meth: 'encryptBytes', 
        resp: mock.cipherBytes,
        params: [
          mock.msgBytes,
          mock.keys.privateKey,
          mock.encryptForKey.publicKey,
          {
            alg: config.defaultConfig.symmAlg,
            length: config.defaultConfig.symmLen
          }
        ]
      },
      {
        mod: keys,
        meth: 'importPublicKey',
        resp: mock.encryptForKey.publicKey,
        params: [
          mock.keyBase64,
          config.defaultConfig.curve,
          KeyUse.Read
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
        meth: 'decryptBytes', 
        resp: mock.msgBytes,
        params: [
          mock.cipherBytes,
          mock.keys.privateKey,
          mock.encryptForKey.publicKey,
          {
            alg: config.defaultConfig.symmAlg,
            length: config.defaultConfig.symmLen
          }
        ]
      },
      {
        mod: keys,
        meth: 'importPublicKey',
        resp: mock.encryptForKey.publicKey,
        params: [
          mock.keyBase64,
          config.defaultConfig.curve,
          KeyUse.Read
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

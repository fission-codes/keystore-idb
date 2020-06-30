import RSAKeyStore from '../src/rsa/keystore'
import keys from '../src/rsa/keys'
import operations from '../src/rsa/operations'
import config, { defaultConfig } from '../src/config'
import idb from '../src/idb'
import { KeyUse, RsaSize, HashAlg, CryptoSystem } from '../src/types'
import { mock, keystoreMethod } from './utils'

jest.mock('../src/idb')

describe("RSAKeyStore", () => {
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

      response = await RSAKeyStore.init({ readKeyName: 'test-read', writeKeyName: 'test-write' })
    })

    it('should initialize a keystore with expected params', () => {
      let cfg = config.normalize({
        type: CryptoSystem.RSA,
        readKeyName: 'test-read',
        writeKeyName: 'test-write'
      })
      const keystore = new RSAKeyStore(cfg, mock.idbStore)
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
        RsaSize.B2048,
        HashAlg.SHA_256,
        KeyUse.Read
      ])
    })

    it('should call makeKeypair with correct params (write key)', () => {
      expect(fakeMake.mock.calls[1]).toEqual([
        RsaSize.B2048,
        HashAlg.SHA_256,
        KeyUse.Write
      ])
    })

  })


  keystoreMethod({
    desc: 'sign',
    type: 'rsa',
    mocks: [
      {
        mod: operations,
        meth: 'signString',
        resp: mock.sigStr,
        params: [
          mock.msgStr,
          mock.writeKeys.privateKey,
          defaultConfig
        ]
      }
    ],
    reqFn: (ks) => ks.sign(mock.msgStr),
    expectedResp: mock.sigStr,
  })


  keystoreMethod({
    desc: 'verify',
    type: 'rsa',
    mocks: [
      {
        mod: operations,
        meth: 'verifyString',
        resp: true,
        params: [
          mock.msgStr,
          mock.sigStr,
          mock.keyBase64,
          defaultConfig
        ]
      }
    ],
    reqFn: (ks) => ks.verify(mock.msgStr, mock.sigStr, mock.keyBase64),
    expectedResp: true,
  })


  keystoreMethod({
    desc: 'encrypt',
    type: 'rsa',
    mocks: [
      {
        mod: operations,
        meth: 'encryptString',
        resp: mock.cipherStr,
        params: [
          mock.msgStr,
          mock.keyBase64,
          defaultConfig
        ]
      }
    ],
    reqFn: (ks) => ks.encrypt(mock.msgStr, mock.keyBase64),
    expectedResp: mock.cipherStr,
  })


  keystoreMethod({
    desc: 'decrypt',
    type: 'rsa',
    mocks: [
      {
        mod: operations,
        meth: 'decryptString',
        resp: mock.msgStr,
        params: [
          mock.cipherStr,
          mock.keys.privateKey,
          defaultConfig
        ]
      },
    ],
    reqFn: (ks) => ks.decrypt(mock.cipherStr, mock.keyBase64),
    expectedResp: mock.msgStr,
  })


  keystoreMethod({
    desc: 'publicReadKey',
    type: 'rsa',
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
    type: 'rsa',
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

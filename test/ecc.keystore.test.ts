import keystore, { ECCKeyStore } from '../src/ecc/keystore'
import keys from '../src/ecc/keys'
import operations from '../src/ecc/operations'
import config from '../src/config'
import { ECC_Curve, KeyUse, CryptoSystem } from '../src/types'
import { mock, keystoreMethod } from './utils'

const sinon = require('sinon')

describe("ECCKeyStore", () => {
  describe("init", () => {
    let fakeGet: sinon.SinonSpy
    let response: any

    beforeAll(async () => {
      sinon.restore()
      fakeGet = sinon.fake.returns(new Promise(r => r(mock.keys)))
      sinon.stub(keys, 'getKey').callsFake(fakeGet)
      response = await keystore.init({ readKeyName: 'test-read', writeKeyName: 'test-write' })
    })

    it('should initialize a keystore with expected params', () => {
      let cfg = config.normalize({
        type: CryptoSystem.ECC,
        readKeyName: 'test-read',
        writeKeyName: 'test-write'
      })
      const keystore = new ECCKeyStore(mock.keys, mock.keys, cfg)
      expect(response).toStrictEqual(keystore)
    })

    it('should call getKey with correct params (read key)', () => {
      expect(fakeGet.args[0]).toEqual([
        ECC_Curve.P_256,
        'test-read',
        KeyUse.Read
      ])
    })

    it('should call getKey with correct params (write key)', () => {
      expect(fakeGet.args[1]).toEqual([
        ECC_Curve.P_256,
        'test-write',
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
        resp: mock.signature,
        params: [
          mock.msgBytes,
          mock.writeKeys.privateKey,
          config.defaultConfig.hashAlg
        ]
      }
    ],
    reqFn: (ks) => ks.sign(mock.msgStr),
    expectedResp: mock.signatureStr,
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
          mock.signature,
          mock.writeKeys.publicKey,
          config.defaultConfig.hashAlg
        ]
      },
      {
        mod: keys,
        meth: 'importPublicKey',
        resp: mock.writeKeys.publicKey,
        params: [
          mock.publicKeyBase64,
          config.defaultConfig.curve,
          KeyUse.Write
        ]
      }
    ],
    reqFn: (ks) => ks.verify(mock.msgStr, mock.signatureStr, mock.publicKeyBase64),
    expectedResp: true,
  })


  keystoreMethod({
    desc: 'encrypt',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'encryptBytes', 
        resp: mock.cipherText,
        params: [
          mock.msgBytes,
          mock.keys.privateKey,
          mock.encryptForKey.publicKey,
          config.defaultConfig.symmAlg
        ]
      },
      {
        mod: keys,
        meth: 'importPublicKey',
        resp: mock.encryptForKey.publicKey,
        params: [
          mock.publicKeyBase64,
          config.defaultConfig.curve,
          KeyUse.Read
        ]
      }
    ],
    reqFn: (ks) => ks.encrypt(mock.msgStr, mock.publicKeyBase64),
    expectedResp: mock.cipherTextStr,
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
          mock.cipherText,
          mock.keys.privateKey,
          mock.encryptForKey.publicKey,
          config.defaultConfig.symmAlg
        ]
      },
      {
        mod: keys,
        meth: 'importPublicKey',
        resp: mock.encryptForKey.publicKey,
        params: [
          mock.publicKeyBase64,
          config.defaultConfig.curve,
          KeyUse.Read
        ]
      }
    ],
    reqFn: (ks) => ks.decrypt(mock.cipherTextStr, mock.publicKeyBase64),
    expectedResp: mock.msgStr,
  })


  keystoreMethod({
    desc: 'publicReadKey',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'getPublicKey', 
        resp: mock.publicKeyBase64,
        params: [
          mock.keys
        ]
      }
    ],
    reqFn: (ks) => ks.publicReadKey(),
    expectedResp: mock.publicKeyBase64,
  })


  keystoreMethod({
    desc: 'publicWriteKey',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'getPublicKey', 
        resp: mock.publicKeyBase64,
        params: [
          mock.writeKeys
        ]
      }
    ],
    reqFn: (ks) => ks.publicWriteKey(),
    expectedResp: mock.publicKeyBase64,
  })

})

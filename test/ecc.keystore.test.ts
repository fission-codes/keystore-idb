import keystore, { ECCKeyStore } from '../src/ecc/keystore'
import keys from '../src/ecc/keys'
import operations from '../src/ecc/operations'
import config from '../src/config'
import { ECC_Curve, KeyUse } from '../src/types'
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
        type: 'ecc',
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
        mod: operations,
        meth: 'importPublicReadKey',
        resp: mock.writeKeys.publicKey,
        params: [
          mock.publicKeyHex,
          config.defaultConfig.curve
        ]
      }
    ],
    reqFn: (ks) => ks.verify(mock.msgStr, mock.signatureStr, mock.publicKeyHex),
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
        mod: operations,
        meth: 'importPublicReadKey',
        resp: mock.encryptForKey.publicKey,
        params: [
          mock.publicKeyHex,
          config.defaultConfig.curve
        ]
      }
    ],
    reqFn: (ks) => ks.encrypt(mock.msgStr, mock.publicKeyHex),
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
        mod: operations,
        meth: 'importPublicReadKey',
        resp: mock.encryptForKey.publicKey,
        params: [
          mock.publicKeyHex,
          config.defaultConfig.curve
        ]
      }
    ],
    reqFn: (ks) => ks.decrypt(mock.cipherTextStr, mock.publicKeyHex),
    expectedResp: mock.msgStr,
  })


  keystoreMethod({
    desc: 'publicReadKey',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'getPublicKey', 
        resp: mock.publicKeyHex,
        params: [
          mock.keys
        ]
      }
    ],
    reqFn: (ks) => ks.publicReadKey(),
    expectedResp: mock.publicKeyHex,
  })


  keystoreMethod({
    desc: 'publicWriteKey',
    type: 'ecc',
    mocks: [
      {
        mod: operations,
        meth: 'getPublicKey', 
        resp: mock.publicKeyHex,
        params: [
          mock.writeKeys
        ]
      }
    ],
    reqFn: (ks) => ks.publicWriteKey(),
    expectedResp: mock.publicKeyHex,
  })

})

import keystore, { ECCKeyStore } from '../src/ecc/keystore'
import keys from '../src/ecc/keys'
import operations from '../src/ecc/operations'
import config from '../src/config'
import { EccCurve, KeyUse, CryptoSystem } from '../src/types'
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
        EccCurve.P_256,
        'test-read',
        KeyUse.Read
      ])
    })

    it('should call getKey with correct params (write key)', () => {
      expect(fakeGet.args[1]).toEqual([
        EccCurve.P_256,
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

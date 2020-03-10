import keystore, { RSAKeyStore } from '../src/rsa/keystore'
import keys from '../src/rsa/keys'
import operations from '../src/rsa/operations'
import config from '../src/config'
import { KeyUse, RsaSize, HashAlg, CryptoSystem } from '../src/types'
import { mock, keystoreMethod } from './utils'

const sinon = require('sinon')

describe("RSAKeyStore", () => {
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
        type: CryptoSystem.RSA,
        readKeyName: 'test-read',
        writeKeyName: 'test-write'
      })
      const keystore = new RSAKeyStore(mock.keys, mock.keys, cfg)
      expect(response).toStrictEqual(keystore)
    })

    it('should call getKey with correct params (read key)', () => {
      expect(fakeGet.args[0]).toEqual([
        RsaSize.B2048,
        HashAlg.SHA_256,
        'test-read',
        KeyUse.Read
      ])
    })

    it('should call getKey with correct params (write key)', () => {
      expect(fakeGet.args[1]).toEqual([
        RsaSize.B2048,
        HashAlg.SHA_256,
        'test-write',
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
        meth: 'signBytes', 
        resp: mock.sigBytes,
        params: [
          mock.msgBytes,
          mock.writeKeys.privateKey,
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
        meth: 'verifyBytes', 
        resp: true,
        params: [
          mock.msgBytes,
          mock.sigBytes,
          mock.writeKeys.publicKey,
        ]
      },
      {
        mod: keys,
        meth: 'importPublicKey',
        resp: mock.writeKeys.publicKey,
        params: [
          mock.keyBase64,
          config.defaultConfig.hashAlg,
          KeyUse.Write
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
        meth: 'encryptBytes', 
        resp: mock.cipherBytes,
        params: [
          mock.msgBytes,
          mock.encryptForKey.publicKey,
        ]
      },
      {
        mod: keys,
        meth: 'importPublicKey',
        resp: mock.encryptForKey.publicKey,
        params: [
          mock.keyBase64,
          config.defaultConfig.hashAlg,
          KeyUse.Read
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
        meth: 'decryptBytes', 
        resp: mock.msgBytes,
        params: [
          mock.cipherBytes,
          mock.keys.privateKey,
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

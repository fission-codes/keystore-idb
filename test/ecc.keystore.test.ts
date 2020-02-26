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
    mockModule: operations,
    mockMethod: 'signBytes', 
    mockResp: mock.signature,
    reqFn: (ks) => ks.sign(mock.msgStr),
    expectedResp: mock.signatureStr,
    expectedParams: [
      mock.msgBytes,
      mock.writeKeys.privateKey,
      config.defaultConfig.hashAlg
    ]
  })


  keystoreMethod({
    desc: 'verify',
    type: 'ecc',
    mockModule: operations,
    mockMethod: 'verifyBytes', 
    mockResp: true,
    reqFn: (ks) => ks.verify(mock.msgStr, mock.signatureStr, mock.writeKeys.publicKey),
    expectedResp: true,
    expectedParams: [
      mock.msgBytes,
      mock.signature,
      mock.writeKeys.publicKey,
      config.defaultConfig.hashAlg
    ]
  })


  keystoreMethod({
    desc: 'encrypt',
    type: 'ecc',
    mockModule: operations,
    mockMethod: 'encryptBytes', 
    mockResp: mock.cipherText,
    reqFn: (ks) => ks.encrypt(mock.msgStr, mock.encryptForKey.publicKey),
    expectedResp: mock.cipherTextStr,
    expectedParams: [
      mock.msgBytes,
      mock.keys.privateKey,
      mock.encryptForKey.publicKey,
      config.defaultConfig.symmAlg
    ]
  })


  keystoreMethod({
    desc: 'decrypt',
    type: 'ecc',
    mockModule: operations,
    mockMethod: 'decryptBytes', 
    mockResp: mock.msgBytes,
    reqFn: (ks) => ks.decrypt(mock.cipherTextStr, mock.encryptForKey.publicKey),
    expectedResp: mock.msgStr,
    expectedParams: [
      mock.cipherText,
      mock.keys.privateKey,
      mock.encryptForKey.publicKey,
      config.defaultConfig.symmAlg
    ]
  })


  keystoreMethod({
    desc: 'publicReadKey',
    type: 'ecc',
    mockModule: operations,
    mockMethod: 'getPublicKey', 
    mockResp: mock.publicKeyHex,
    reqFn: (ks) => ks.publicReadKey(),
    expectedResp: mock.publicKeyHex,
    expectedParams: [
      mock.keys
    ]
  })


  keystoreMethod({
    desc: 'publicWriteKey',
    type: 'ecc',
    mockModule: operations,
    mockMethod: 'getPublicKey', 
    mockResp: mock.publicKeyHex,
    reqFn: (ks) => ks.publicWriteKey(),
    expectedResp: mock.publicKeyHex,
    expectedParams: [
      mock.writeKeys
    ]
  })

})

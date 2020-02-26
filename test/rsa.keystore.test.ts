import keystore, { RSAKeyStore } from '../src/rsa/keystore'
import keys from '../src/rsa/keys'
import operations from '../src/rsa/operations'
import config from '../src/config'
import { KeyUse, RSA_Size, HashAlg } from '../src/types'
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
        type: 'rsa',
        readKeyName: 'test-read',
        writeKeyName: 'test-write'
      })
      const keystore = new RSAKeyStore(mock.keys, mock.keys, cfg)
      expect(response).toStrictEqual(keystore)
    })

    it('should call getKey with correct params (read key)', () => {
      expect(fakeGet.args[0]).toEqual([
        RSA_Size.B2048,
        HashAlg.SHA_256,
        'test-read',
        KeyUse.Read
      ])
    })

    it('should call getKey with correct params (write key)', () => {
      expect(fakeGet.args[1]).toEqual([
        RSA_Size.B2048,
        HashAlg.SHA_256,
        'test-write',
        KeyUse.Write
      ])
    })
  })


  keystoreMethod({
    desc: 'sign',
    type: 'rsa',
    mockModule: operations,
    mockMethod: 'signBytes', 
    mockResp: mock.signature,
    reqFn: (ks) => ks.sign(mock.msgStr),
    expectedResp: mock.signatureStr,
    expectedParams: [
      mock.msgBytes,
      mock.writeKeys.privateKey,
    ]
  })


  keystoreMethod({
    desc: 'verify',
    type: 'rsa',
    mockModule: operations,
    mockMethod: 'verifyBytes', 
    mockResp: true,
    reqFn: (ks) => ks.verify(mock.msgStr, mock.signatureStr, mock.writeKeys.publicKey),
    expectedResp: true,
    expectedParams: [
      mock.msgBytes,
      mock.signature,
      mock.writeKeys.publicKey,
    ]
  })


  keystoreMethod({
    desc: 'encrypt',
    type: 'rsa',
    mockModule: operations,
    mockMethod: 'encryptBytes', 
    mockResp: mock.cipherText,
    reqFn: (ks) => ks.encrypt(mock.msgStr, mock.encryptForKey.publicKey),
    expectedResp: mock.cipherTextStr,
    expectedParams: [
      mock.msgBytes,
      mock.encryptForKey.publicKey,
    ]
  })


  keystoreMethod({
    desc: 'decrypt',
    type: 'rsa',
    mockModule: operations,
    mockMethod: 'decryptBytes', 
    mockResp: mock.msgBytes,
    reqFn: (ks) => ks.decrypt(mock.cipherTextStr, mock.encryptForKey.publicKey),
    expectedResp: mock.msgStr,
    expectedParams: [
      mock.cipherText,
      mock.keys.privateKey,
    ]
  })


  keystoreMethod({
    desc: 'publicReadKey',
    type: 'rsa',
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
    type: 'rsa',
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

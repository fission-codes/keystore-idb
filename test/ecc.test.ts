import ecc from '../src/ecc'
import errors from '../src/errors'
import utils from '../src/utils'
import { KeyUse, ECC_Curve, HashAlg, SymmAlg } from '../src/types'
import { mock, cryptoMethod, idbMethod } from './utils'

const sinon = require('sinon')

describe('ecc', () => {

  beforeEach(() => sinon.restore())

  cryptoMethod({
    desc: 'makeKey',
    setMock: fake => window.crypto.subtle.generateKey = fake,
    mockResp: mock.keys,
    simpleReq: () => ecc.makeKey(ECC_Curve.P_256, KeyUse.Read),
    simpleParams: [
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
        [ 'deriveKey', 'deriveBits']
    ],
    paramChecks: [
      {
        desc: 'handles multiple key algorithms',
        req: () => ecc.makeKey(ECC_Curve.P_521, KeyUse.Read),
        params: (params: any) => params[0]?.namedCurve === 'P-521'
      },
      {
        desc: 'handles write keys',
        req: () => ecc.makeKey(ECC_Curve.P_256, KeyUse.Write),
        params: [
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['sign', 'verify']
        ]
      }
    ],
    shouldThrows: [
      {
        desc: 'throws an error when passing in an invalid use',
        req: () => ecc.makeKey(ECC_Curve.P_256, 'signature' as any),
        error: errors.InvalidKeyUse
      }
    ]
  })


  describe('getKey', () => {
    idbMethod({
      desc: 'key does not exist',
      req: () => ecc.getKey(ECC_Curve.P_256, 'read-key', KeyUse.Read),
      expectedResponse: mock.keys,
      fakeMakeResp: mock.keys,
      putParams: [
        'read-key',
        mock.keys
      ],
      getParams: [
        'read-key'
      ],
      makeParams: [
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveKey', 'deriveBits']
      ],
      putCount: 1,
      getCount: 1,
      makeCount: 1,
    })

    idbMethod({
      desc: 'key does exist',
      req: () => ecc.getKey(ECC_Curve.P_256, 'read-key', KeyUse.Read),
      expectedResponse: mock.keys,
      fakeGetResp: mock.keys,
      getParams: [
        'read-key'
      ],
      putCount: 0,
      getCount: 1,
      makeCount: 0,
    })
  })


  cryptoMethod({
    desc: 'signBytes',
    setMock: fake => window.crypto.subtle.sign = fake,
    mockResp: mock.signature,
    simpleReq: () => ecc.signBytes(mock.msgBytes, mock.keys.privateKey, HashAlg.SHA_256),
    simpleParams: [
      { name: 'ECDSA', hash: {name: 'SHA-256' }},
      mock.keys.privateKey,
      mock.msgBytes
    ],
    paramChecks: [
      {
        desc: 'handles multiple hash algorithms',
        req: () => ecc.signBytes(mock.msgBytes, mock.keys.privateKey, HashAlg.SHA_512),
        params: (params: any) => params[0]?.hash?.name === 'SHA-512'
      },
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'verifyBytes',
    setMock: fake => window.crypto.subtle.verify = fake,
    mockResp: true,
    simpleReq: () => ecc.verifyBytes(mock.msgBytes, mock.signature, mock.keys.publicKey, HashAlg.SHA_256),
    simpleParams: [
      { name: 'ECDSA', hash: {name: 'SHA-256' }},
      mock.keys.publicKey,
      mock.signature,
      mock.msgBytes
    ],
    paramChecks: [
      {
        desc: 'handles multiple hash algorithms',
        req: () => ecc.verifyBytes(mock.msgBytes, mock.signature, mock.keys.publicKey, HashAlg.SHA_512),
        params: (params: any) => params[0]?.hash?.name === 'SHA-512'
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getSharedKey',
    setMock: fake => window.crypto.subtle.deriveKey = fake,
    mockResp: mock.symmKey,
    simpleReq: () => ecc.getSharedKey(mock.keys.privateKey, mock.keys.publicKey, SymmAlg.AES_CTR),
    simpleParams: [
      { name: 'ECDH', public: mock.keys.publicKey },
      mock.keys.privateKey,
      { name: 'AES-CTR', length: 256 },
      false,
      ['encrypt', 'decrypt']
    ],
    paramChecks: [
      {
        desc: 'handles multiple symm key algorithms',
        req: () => ecc.getSharedKey(mock.keys.privateKey, mock.keys.publicKey, SymmAlg.AES_GCM),
        params: (params: any) => params[2]?.name === 'AES-GCM'
      },
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'encryptBytes',
    setMock: fake => {
      window.crypto.subtle.encrypt = fake
      window.crypto.subtle.deriveKey = sinon.fake.returns(new Promise(r => r(mock.symmKey)))
    },
    mockResp: mock.cipherText,
    simpleReq: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, SymmAlg.AES_CTR),
    simpleParams: [
      { name: 'AES-CTR',
        counter: new Uint8Array(16),
        length: 128
      },
      mock.symmKey,
      mock.msgBytes
    ],
    paramChecks: [
      {
        desc: 'handles multiple symm key algorithms',
        req: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, SymmAlg.AES_GCM),
        params: (params: any) => params[0]?.name === 'AES-GCM'
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'decryptBytes',
    setMock: fake => {
      window.crypto.subtle.decrypt = fake
      window.crypto.subtle.deriveKey = sinon.fake.returns(new Promise(r => r(mock.symmKey)))
    },
    mockResp: mock.msgBytes,
    simpleReq: () => ecc.decryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, SymmAlg.AES_CTR),
    simpleParams: [
      { name: 'AES-CTR',
        counter: new Uint8Array(16),
        length: 128
      },
      mock.symmKey,
      mock.cipherText
    ],
    paramChecks: [
      {
        desc: 'handles multiple symm key algorithms',
        req: () => ecc.decryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, SymmAlg.AES_GCM),
        params: (params: any) => params[0]?.name === 'AES-GCM'
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getPublicKey',
    setMock: fake => window.crypto.subtle.exportKey = fake,
    mockResp: utils.hexToArrBuf(mock.publicKeyHex),
    expectedResp: mock.publicKeyHex,
    simpleReq: () => ecc.getPublicKey(mock.keys),
    simpleParams: [
      'raw',
      mock.keys.publicKey
    ],
    paramChecks: [],
    shouldThrows: []
  })

})

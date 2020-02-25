import ecc from '../src/ecc'
import errors from '../src/errors'
import utils from '../src/utils'
import { KeyUse } from '../src/types'
import { cryptoMethod } from './utils'

const sinon = require('sinon')

const mock = {
  keys: {
    publicKey: { type: 'pub' } as any,
    privateKey: { type: 'priv' } as any
  } as any,
  symmKey: { type: 'symm' } as any,
  publicKeyStr: 'abcdef1234567890',
  msgBytes: utils.strToArrBuf("test msg bytes", 8),
  signature: utils.strToArrBuf("test signature", 8),
  cipherText: utils.strToArrBuf("test encrypted bytes", 8),
}

describe('ecc', () => {

  beforeEach(() => sinon.restore())

  cryptoMethod({
    desc: 'makeKey',
    setMock: fake => window.crypto.subtle.generateKey = fake,
    simpleReq: () => ecc.makeKey('P-256', KeyUse.Read),
    mockResp: mock.keys,
    paramChecks: [
      {
        desc: 'handles read keys',
        req: () => ecc.makeKey('P-256', KeyUse.Read),
        params: [
          { name: 'ECDH', namedCurve: 'P-256' },
          false,
          [ 'deriveKey', 'deriveBits']
        ]
      },
      {
        desc: 'handles multiple key algorithms',
        req: () => ecc.makeKey('P-521', KeyUse.Read),
        params: [
          { name: 'ECDH', namedCurve: 'P-521' },
          false,
          [ 'deriveKey', 'deriveBits']
        ]
      },
      {
        desc: 'handles write keys',
        req: () => ecc.makeKey('P-256', KeyUse.Write),
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
        req: () => ecc.makeKey('P-256', 'signature' as any),
        error: errors.InvalidKeyUse
      }
    ]
  })


  cryptoMethod({
    desc: 'signBytes',
    setMock: fake => window.crypto.subtle.sign = fake,
    simpleReq: () => ecc.signBytes(mock.msgBytes, mock.keys.privateKey, 'SHA-256'),
    mockResp: mock.signature,
    paramChecks: [
      {
        desc: 'correctly passes params',
        req: () => ecc.signBytes(mock.msgBytes, mock.keys.privateKey, 'SHA-256'),
        params: [
          { name: 'ECDSA', hash: {name: 'SHA-256' }},
          mock.keys.privateKey,
          mock.msgBytes
        ]
      },
      {
        desc: 'handles multiple hash algorithms',
        req: () => ecc.signBytes(mock.msgBytes, mock.keys.privateKey, 'SHA-512'),
        params: [
          { name: 'ECDSA', hash: {name: 'SHA-512' }},
          mock.keys.privateKey,
          mock.msgBytes
        ]
      },
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'verifyBytes',
    setMock: fake => window.crypto.subtle.verify = fake,
    simpleReq: () => ecc.verifyBytes(mock.msgBytes, mock.signature, mock.keys.publicKey, 'SHA-256'),
    mockResp: true,
    paramChecks: [
      {
        desc: 'correctly passes params',
        req: () => ecc.verifyBytes(mock.msgBytes, mock.signature, mock.keys.publicKey, 'SHA-256'),
        params: [
          { name: 'ECDSA', hash: {name: 'SHA-256' }},
          mock.keys.publicKey,
          mock.signature,
          mock.msgBytes
        ]
      },
      {
        desc: 'handles multiple hash algorithms',
        req: () => ecc.verifyBytes(mock.msgBytes, mock.signature, mock.keys.publicKey, 'SHA-512'),
        params: [
          { name: 'ECDSA', hash: {name: 'SHA-512' }},
          mock.keys.publicKey,
          mock.signature,
          mock.msgBytes
        ]
      },
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getSharedKey',
    setMock: fake => window.crypto.subtle.deriveKey = fake,
    simpleReq: () => ecc.getSharedKey(mock.keys.privateKey, mock.keys.publicKey, 'AES-CTR'),
    mockResp: mock.symmKey,
    paramChecks: [
      {
        desc: 'correctly passes params',
        req: () => ecc.getSharedKey(mock.keys.privateKey, mock.keys.publicKey, 'AES-CTR'),
        params: [
          { name: 'ECDH', public: mock.keys.publicKey },
          mock.keys.privateKey,
          { name: 'AES-CTR', length: 256 },
          false,
          ['encrypt', 'decrypt']
        ]
      },
      {
        desc: 'handles multiple symm key algorithms',
        req: () => ecc.getSharedKey(mock.keys.privateKey, mock.keys.publicKey, 'AES-GCM'),
        params: [
          { name: 'ECDH', public: mock.keys.publicKey },
          mock.keys.privateKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        ]
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
    simpleReq: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, 'AES-CTR'),
    mockResp: mock.cipherText,
    paramChecks: [
      {
        desc: 'correctly passes params',
        req: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, 'AES-CTR'),
        params: [
          { name: 'AES-CTR',
            counter: new Uint8Array(16),
            length: 128
          },
          mock.symmKey,
          mock.msgBytes
        ]
      },
      {
        desc: 'handles multiple symm key algorithms',
        req: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, 'AES-GCM'),
        params: [
          { name: 'AES-GCM',
            counter: new Uint8Array(16),
            length: 128
          },
          mock.symmKey,
          mock.msgBytes
        ]
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
    simpleReq: () => ecc.decryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, 'AES-CTR'),
    mockResp: mock.msgBytes,
    paramChecks: [
      {
        desc: 'correctly passes params',
        req: () => ecc.decryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, 'AES-CTR'),
        params: [
          { name: 'AES-CTR',
            counter: new Uint8Array(16),
            length: 128
          },
          mock.symmKey,
          mock.cipherText
        ]
      },
      {
        desc: 'handles multiple symm key algorithms',
        req: () => ecc.decryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, 'AES-GCM'),
        params: [
          { name: 'AES-GCM',
            counter: new Uint8Array(16),
            length: 128
          },
          mock.symmKey,
          mock.cipherText
        ]
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getPublicKey',
    setMock: fake => window.crypto.subtle.exportKey = fake,
    simpleReq: () => ecc.getPublicKey(mock.keys),
    mockResp: utils.hexToArrBuf(mock.publicKeyStr),
    expectedResp: mock.publicKeyStr,
    paramChecks: [
      {
        desc: 'correctly passes params',
        req: () => ecc.getPublicKey(mock.keys),
        params: [
          'raw',
          mock.keys.publicKey
        ]
      }
    ],
    shouldThrows: []
  })

})

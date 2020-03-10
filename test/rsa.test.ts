import rsa from '../src/rsa'
import errors from '../src/errors'
import utils from '../src/utils'
import { KeyUse, RsaSize, HashAlg } from '../src/types'
import { mock, cryptoMethod, idbMethod } from './utils'

const sinon = require('sinon')

describe('rsa', () => {

  beforeEach(() => sinon.restore())

  cryptoMethod({
    desc: 'makeKey',
    setMock: fake => window.crypto.subtle.generateKey = fake,
    mockResp: mock.keys,
    simpleReq: () => rsa.makeKey(RsaSize.B2048, HashAlg.SHA_256, KeyUse.Read),
    simpleParams: [
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: utils.publicExponent(),
        hash: { name: 'SHA-256' }
      },
      false,
      ['encrypt', 'decrypt']
    ],
    paramChecks: [
      {
        desc: 'handles write keys',
        req: () => rsa.makeKey(RsaSize.B2048, HashAlg.SHA_256, KeyUse.Write),
        params: [
          {
            name: 'RSA-PSS',
            modulusLength: 2048,
            publicExponent: utils.publicExponent(),
            hash: { name: 'SHA-256' }
          },
          false,
          ['sign', 'verify']
        ]
      },
      {
        desc: 'handles multiple key sizes',
        req: () => rsa.makeKey(RsaSize.B4096, HashAlg.SHA_256, KeyUse.Write),
        params: (params: any) => params[0]?.modulusLength === 4096
      },
      {
        desc: 'handles multiple hash algorithms',
        req: () => rsa.makeKey(RsaSize.B2048, HashAlg.SHA_512, KeyUse.Write),
        params: (params: any) => params[0]?.hash?.name === 'SHA-512'
      }
    ],
    shouldThrows: [
      {
        desc: 'throws an error when passing in an invalid use',
        req: () => rsa.makeKey(RsaSize.B2048, HashAlg.SHA_256, 'sigBytes' as any),
        error: errors.InvalidKeyUse
      }
    ]
  })


  describe('getKey', () => {
    idbMethod({
      desc: 'key does not exist',
      req: () => rsa.getKey(RsaSize.B2048, HashAlg.SHA_256, 'read-key', KeyUse.Read),
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
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: utils.publicExponent(),
          hash: { name: 'SHA-256' }
        },
        false,
        ['encrypt', 'decrypt']
      ],
      putCount: 1,
      getCount: 1,
      makeCount: 1,
    })

    idbMethod({
      desc: 'key does exist',
      req: () => rsa.getKey(RsaSize.B2048, HashAlg.SHA_256, 'read-key', KeyUse.Read),
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
    desc: 'importPublicReadKey',
    setMock: fake => window.crypto.subtle.importKey = fake,
    mockResp: mock.keys.publicKey,
    expectedResp: mock.keys.publicKey,
    simpleReq: () => rsa.importPublicKey(mock.keyBase64, HashAlg.SHA_256, KeyUse.Read),
    simpleParams: [
      'spki',
      utils.base64ToArrBuf(mock.keyBase64),
      { name: 'RSA-OAEP', hash: {name: 'SHA-256'}},
      true,
      ['encrypt']
    ],
    paramChecks: [
      {
        desc: 'handles multiple hash algs',
        req: () => rsa.importPublicKey(mock.keyBase64, HashAlg.SHA_512, KeyUse.Read),
        params: (params: any) => params[2]?.hash?.name === 'SHA-512'
      },
      {
        desc: 'handles write keys',
        req: () => rsa.importPublicKey(mock.keyBase64, HashAlg.SHA_256, KeyUse.Write),
        params: [
          'spki',
          utils.base64ToArrBuf(mock.keyBase64),
          { name: 'RSA-PSS', hash: {name: 'SHA-256'}},
          true,
          ['verify']
        ]
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'signBytes',
    setMock: fake => window.crypto.subtle.sign = fake,
    mockResp: mock.sigBytes,
    simpleReq: () => rsa.signBytes(mock.msgBytes, mock.keys.privateKey),
    simpleParams: [
      { name: 'RSA-PSS', saltLength: 128},
      mock.keys.privateKey,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'verifyBytes',
    setMock: fake => window.crypto.subtle.verify = fake,
    mockResp: true,
    simpleReq: () => rsa.verifyBytes(mock.msgBytes, mock.sigBytes, mock.keys.publicKey),
    simpleParams: [
      { name: 'RSA-PSS', saltLength: 128},
      mock.keys.publicKey,
      mock.sigBytes,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'encryptBytes',
    setMock: fake => window.crypto.subtle.encrypt = fake,
    mockResp: mock.cipherBytes,
    simpleReq: () => rsa.encryptBytes(mock.msgBytes, mock.keys.publicKey),
    simpleParams: [
      { name: 'RSA-OAEP' },
      mock.keys.publicKey,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'decryptBytes',
    setMock: fake => window.crypto.subtle.decrypt = fake,
    mockResp: mock.msgBytes,
    simpleReq: () => rsa.decryptBytes(mock.cipherBytes, mock.keys.privateKey),
    simpleParams: [
      { name: 'RSA-OAEP' },
      mock.keys.privateKey,
      mock.cipherBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getPublicKey',
    setMock: fake => window.crypto.subtle.exportKey = fake,
    mockResp: utils.base64ToArrBuf(mock.keyBase64),
    expectedResp: mock.keyBase64,
    simpleReq: () => rsa.getPublicKey(mock.keys),
    simpleParams: [
      'spki',
      mock.keys.publicKey
    ],
    paramChecks: [],
    shouldThrows: []
  })

})

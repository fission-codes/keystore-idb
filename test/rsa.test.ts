import rsa from '../src/rsa'
import errors from '../src/errors'
import utils from '../src/utils'
import { KeyUse, RSA_Size, HashAlg } from '../src/types'
import { cryptoMethod, mock } from './utils'

const sinon = require('sinon')
window.atob = require('atob')
window.btoa = require('btoa')

describe('rsa', () => {

  beforeEach(() => sinon.restore())

  cryptoMethod({
    desc: 'makeKey',
    setMock: fake => window.crypto.subtle.generateKey = fake,
    mockResp: mock.keys,
    simpleReq: () => rsa.makeKey(RSA_Size.B2048, HashAlg.SHA_256, KeyUse.Read),
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
        req: () => rsa.makeKey(RSA_Size.B2048, HashAlg.SHA_256, KeyUse.Write),
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
        req: () => rsa.makeKey(RSA_Size.B4096, HashAlg.SHA_256, KeyUse.Write),
        params: (params: any) => params[0]?.modulusLength === 4096
      },
      {
        desc: 'handles multiple hash algorithms',
        req: () => rsa.makeKey(RSA_Size.B2048, HashAlg.SHA_512, KeyUse.Write),
        params: (params: any) => params[0]?.hash?.name === 'SHA-512'
      }
    ],
    shouldThrows: [
      {
        desc: 'throws an error when passing in an invalid use',
        req: () => rsa.makeKey(RSA_Size.B2048, HashAlg.SHA_256, 'signature' as any),
        error: errors.InvalidKeyUse
      }
    ]
  })


  cryptoMethod({
    desc: 'signBytes',
    setMock: fake => window.crypto.subtle.sign = fake,
    mockResp: mock.signature,
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
    simpleReq: () => rsa.verifyBytes(mock.msgBytes, mock.signature, mock.keys.publicKey),
    simpleParams: [
      { name: 'RSA-PSS', saltLength: 128},
      mock.keys.publicKey,
      mock.signature,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'encryptBytes',
    setMock: fake => window.crypto.subtle.encrypt = fake,
    mockResp: mock.cipherText,
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
    simpleReq: () => rsa.decryptBytes(mock.cipherText, mock.keys.privateKey),
    simpleParams: [
      { name: 'RSA-OAEP' },
      mock.keys.privateKey,
      mock.cipherText
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getPublicKey',
    setMock: fake => window.crypto.subtle.exportKey = fake,
    mockResp: utils.base64ToArrBuf(mock.publicKeyBase64),
    expectedResp: `-----BEGIN PUBLIC KEY-----\n${mock.publicKeyBase64}\n-----END PUBLIC KEY-----`,
    simpleReq: () => rsa.getPublicKey(mock.keys),
    simpleParams: [
      'spki',
      mock.keys.publicKey
    ],
    paramChecks: [],
    shouldThrows: []
  })

})

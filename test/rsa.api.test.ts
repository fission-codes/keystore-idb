import { webcrypto } from 'one-webcrypto'
import * as uint8arrays from 'uint8arrays'
import rsa from '../src/rsa'
import errors from '../src/errors'
import utils from '../src/utils'
import { DEFAULT_HASH_ALG } from '../src/constants'
import { KeyUse, RsaSize, HashAlg } from '../src/types'
import { mock, cryptoMethod } from './utils'

describe('rsa API', () => {

  cryptoMethod({
    desc: 'makeKeypair',
    setMock: fake => webcrypto.subtle.generateKey = fake,
    mockResp: mock.keys,
    simpleReq: () => rsa.makeKeypair(RsaSize.B2048, HashAlg.SHA_256, KeyUse.Exchange),
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
        req: () => rsa.makeKeypair(RsaSize.B2048, HashAlg.SHA_256, KeyUse.Write),
        params: [
          {
            name: 'RSASSA-PKCS1-v1_5',
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
        req: () => rsa.makeKeypair(RsaSize.B4096, HashAlg.SHA_256, KeyUse.Write),
        params: (params: any) => params[0]?.modulusLength === 4096
      },
      {
        desc: 'handles multiple hash algorithms',
        req: () => rsa.makeKeypair(RsaSize.B2048, HashAlg.SHA_512, KeyUse.Write),
        params: (params: any) => params[0]?.hash?.name === 'SHA-512'
      }
    ],
    shouldThrows: [
      {
        desc: 'throws an error when passing in an invalid use',
        req: () => rsa.makeKeypair(RsaSize.B2048, HashAlg.SHA_256, 'sigBytes' as any),
        error: errors.InvalidKeyUse
      }
    ]
  })


  cryptoMethod({
    desc: 'importPublicExchangeKey',
    setMock: fake => webcrypto.subtle.importKey = fake,
    mockResp: mock.keys.publicKey,
    expectedResp: mock.keys.publicKey,
    simpleReq: () => rsa.importPublicKey(mock.keyBase64, HashAlg.SHA_256, KeyUse.Exchange),
    simpleParams: [
      'spki',
      uint8arrays.fromString(mock.keyBase64, "base64pad").buffer,
      { name: 'RSA-OAEP', hash: {name: 'SHA-256'}},
      true,
      ['encrypt']
    ],
    paramChecks: [
      {
        desc: 'handles multiple hash algs',
        req: () => rsa.importPublicKey(mock.keyBase64, HashAlg.SHA_512, KeyUse.Exchange),
        params: (params: any) => params[2]?.hash?.name === 'SHA-512'
      },
      {
        desc: 'handles write keys',
        req: () => rsa.importPublicKey(mock.keyBase64, HashAlg.SHA_256, KeyUse.Write),
        params: [
          'spki',
          uint8arrays.fromString(mock.keyBase64).buffer,
          { name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}},
          true,
          ['verify']
        ]
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'sign',
    setMock: fake => webcrypto.subtle.sign = fake,
    mockResp: mock.sigBytes,
    simpleReq: () => rsa.sign(
      mock.msgBytes,
      mock.keys.privateKey
    ),
    simpleParams: [
      { name: 'RSASSA-PKCS1-v1_5', saltLength: 128 },
      mock.keys.privateKey,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'sign',
    setMock: fake => webcrypto.subtle.sign = fake,
    mockResp: mock.sigBytes,
    simpleReq: () => rsa.sign(
      mock.msgStr,
      mock.keys.privateKey,
    ),
    simpleParams: [
      { name: 'RSASSA-PKCS1-v1_5', saltLength: 128 },
      mock.keys.privateKey,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'verify',
    setMock: fake => webcrypto.subtle.verify = fake,
    mockResp: true,
    simpleReq: () => rsa.verify(
      mock.msgBytes,
      mock.sigBytes,
      mock.keys.publicKey
    ),
    simpleParams: [
      { name: 'RSASSA-PKCS1-v1_5', saltLength: 128 },
      mock.keys.publicKey,
      mock.sigBytes,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'verify',
    setMock: fake => webcrypto.subtle.verify = fake,
    mockResp: true,
    simpleReq: () => rsa.verify(
      mock.msgStr,
      mock.sigStr,
      mock.keyBase64,
      DEFAULT_HASH_ALG
    ),
    simpleParams: [
      { name: 'RSASSA-PKCS1-v1_5', saltLength: 128 },
      mock.keys.publicKey,
      mock.sigBytes,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'encrypt',
    setMock: fake => webcrypto.subtle.encrypt = fake,
    mockResp: mock.cipherBytes,
    simpleReq: () => rsa.encrypt(
      mock.msgBytes,
      mock.keys.publicKey
    ),
    simpleParams: [
      { name: 'RSA-OAEP' },
      mock.keys.publicKey,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'encrypt',
    setMock: fake => webcrypto.subtle.encrypt = fake,
    mockResp: mock.cipherBytes,
    simpleReq: () => rsa.encrypt(
      mock.msgStr,
      mock.keyBase64,
      DEFAULT_HASH_ALG
    ),
    simpleParams: [
      { name: 'RSA-OAEP' },
      mock.keys.publicKey,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'decrypt',
    setMock: fake => webcrypto.subtle.decrypt = fake,
    mockResp: mock.msgBytes,
    simpleReq: () => rsa.decrypt(
      mock.cipherBytes,
      mock.keys.privateKey
    ),
    simpleParams: [
      { name: 'RSA-OAEP' },
      mock.keys.privateKey,
      mock.cipherBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'decrypt',
    setMock: fake => webcrypto.subtle.decrypt = fake,
    mockResp: mock.msgBytes,
    simpleReq: () => rsa.decrypt(
      mock.cipherStr,
      mock.keys.privateKey,
    ),
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
    setMock: fake => webcrypto.subtle.exportKey = fake,
    mockResp: uint8arrays.fromString(mock.keyBase64, "base64pad").buffer,
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

import ecc from '../src/ecc'
import errors from '../src/errors'
import utils from '../src/utils'
import { DEFAULT_CHAR_SIZE, DEFAULT_ECC_CURVE } from '../src/constants'
import { KeyUse, EccCurve, HashAlg, SymmAlg, SymmKeyLength } from '../src/types'
import { crypto, webcrypto } from '../src/webcrypto'
import { mock, cryptoMethod, arrBufEq } from './utils'

describe('ecc', () => {

  cryptoMethod({
    desc: 'makeKeypair',
    setMock: fake => webcrypto.generateKey = fake,
    mockResp: mock.keys,
    simpleReq: () => ecc.makeKeypair(EccCurve.P_256, KeyUse.Exchange),
    simpleParams: [
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
        [ 'deriveKey', 'deriveBits']
    ],
    paramChecks: [
      {
        desc: 'handles multiple key algorithms',
        req: () => ecc.makeKeypair(EccCurve.P_521, KeyUse.Exchange),
        params: (params: any) => params[0]?.namedCurve === 'P-521'
      },
      {
        desc: 'handles write keys',
        req: () => ecc.makeKeypair(EccCurve.P_256, KeyUse.Write),
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
        req: () => ecc.makeKeypair(EccCurve.P_256, 'sigBytes' as any),
        error: errors.InvalidKeyUse
      }
    ]
  })


  cryptoMethod({
    desc: 'importPublicExchangeKey',
    setMock: fake => webcrypto.importKey = fake,
    mockResp: mock.keys.publicKey,
    expectedResp: mock.keys.publicKey,
    simpleReq: () => ecc.importPublicKey(mock.keyBase64, EccCurve.P_256, KeyUse.Exchange),
    simpleParams: [
      'raw',
      utils.base64ToArrBuf(mock.keyBase64),
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    ],
    paramChecks: [
      {
        desc: 'handles multiple curves',
        req: () => ecc.importPublicKey(mock.keyBase64, EccCurve.P_521, KeyUse.Exchange),
        params: (params: any) => params[2]?.namedCurve === 'P-521'
      },
      {
        desc: 'handles write keys',
        req: () => ecc.importPublicKey(mock.keyBase64, EccCurve.P_256, KeyUse.Write),
        params: [
          'raw',
          utils.base64ToArrBuf(mock.keyBase64),
          { name: 'ECDSA', namedCurve: 'P-256' },
          true,
          ['verify']
        ]
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'sign',
    setMock: fake => webcrypto.sign = fake,
    mockResp: mock.sigBytes,
    simpleReq: () => ecc.sign(
      mock.msgBytes,
      mock.keys.privateKey
    ),
    simpleParams: [
      { name: 'ECDSA', hash: { name: 'SHA-256' }},
      mock.keys.privateKey,
      mock.msgBytes
    ],
    paramChecks: [
      {
        desc: 'handles multiple hash algorithms',
        req: () => ecc.sign(
          mock.msgBytes,
          mock.keys.privateKey,
          DEFAULT_CHAR_SIZE,
          HashAlg.SHA_512
        ),
        params: (params: any) => params[0]?.hash?.name === 'SHA-512'
      },
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'sign',
    setMock: fake => webcrypto.sign = fake,
    mockResp: mock.sigBytes,
    simpleReq: () => ecc.sign(
      mock.msgStr,
      mock.keys.privateKey,
      DEFAULT_CHAR_SIZE,
      HashAlg.SHA_256
    ),
    simpleParams: [
      { name: 'ECDSA', hash: { name: 'SHA-256' }},
      mock.keys.privateKey,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'verify',
    setMock: fake => webcrypto.verify = fake,
    mockResp: true,
    simpleReq: () => ecc.verify(
      mock.msgBytes,
      mock.sigBytes,
      mock.keys.publicKey
    ),
    simpleParams: [
      { name: 'ECDSA', hash: { name: 'SHA-256' }},
      mock.keys.publicKey,
      mock.sigBytes,
      mock.msgBytes
    ],
    paramChecks: [
      {
        desc: 'handles multiple hash algorithms',
        req: () => ecc.verify(
          mock.msgBytes,
          mock.sigBytes,
          mock.keys.publicKey,
          DEFAULT_CHAR_SIZE,
          DEFAULT_ECC_CURVE,
          HashAlg.SHA_512
        ),
        params: (params: any) => params[0]?.hash?.name === 'SHA-512'
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'verify',
    setMock: fake => webcrypto.verify = fake,
    mockResp: true,
    simpleReq: () => ecc.verify(
      mock.msgStr,
      mock.sigStr,
      mock.keyBase64,
      DEFAULT_CHAR_SIZE,
      DEFAULT_ECC_CURVE,
      HashAlg.SHA_256
    ),
    simpleParams: [
      { name: 'ECDSA', hash: { name: 'SHA-256' }},
      mock.keys.publicKey,
      mock.sigBytes,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'encrypt',
    setMock: fake => {
      webcrypto.encrypt = fake
      webcrypto.deriveKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
      crypto.getRandomValues = jest.fn(() => new Promise(r => r(new Uint8Array(16)))) as any
    },
    mockResp: mock.cipherBytes,
    simpleReq: () => ecc.encrypt(
      mock.msgBytes,
      mock.keys.privateKey,
      mock.keys.publicKey
    ),
    simpleParams: [
      { name: 'AES-CTR',
        counter: new Uint8Array(16),
        length: 64
      },
      mock.symmKey,
      mock.msgBytes
    ],
    paramChecks: [
      {
        desc: 'handles multiple symm key algorithms',
        req: () => ecc.encrypt(
          mock.msgBytes,
          mock.keys.privateKey,
          mock.keys.publicKey,
          DEFAULT_CHAR_SIZE,
          DEFAULT_ECC_CURVE,
          { alg: SymmAlg.AES_CBC }
        ),
        params: (params: any) => params[0]?.name === 'AES-CBC'
      },
      {
        desc: 'handles an IV with AES-CTR',
        req: () => ecc.encrypt(
          mock.msgBytes,
          mock.keys.privateKey,
          mock.keys.publicKey,
          DEFAULT_CHAR_SIZE,
          DEFAULT_ECC_CURVE,
          { iv: mock.iv }
        ),
        params: (params: any) => arrBufEq(params[0]?.counter, mock.iv)
      },
      {
        desc: 'handles an IV with AES-CBC',
        req: () => ecc.encrypt(
          mock.msgBytes,
          mock.keys.privateKey,
          mock.keys.publicKey,
          DEFAULT_CHAR_SIZE,
          DEFAULT_ECC_CURVE,
          { alg: SymmAlg.AES_CBC, iv: mock.iv }
        ),
        params: (params: any) => params[0]?.iv === mock.iv
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'encrypt',
    setMock: fake => {
      webcrypto.encrypt = fake
      webcrypto.deriveKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
      crypto.getRandomValues = jest.fn(() => new Promise(r => r(new Uint8Array(16)))) as any
    },
    mockResp: mock.cipherBytes,
    simpleReq: () => ecc.encrypt(
      mock.msgStr,
      mock.keys.privateKey,
      mock.keyBase64,
      DEFAULT_CHAR_SIZE,
      DEFAULT_ECC_CURVE
    ),
    simpleParams: [
      { name: 'AES-CTR',
        counter: new Uint8Array(16),
        length: 64
      },
      mock.symmKey,
      mock.msgBytes
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'decrypt',
    setMock: fake => {
      webcrypto.decrypt = fake
      webcrypto.deriveKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
    },
    mockResp: mock.msgBytes,
    simpleReq: () => ecc.decrypt(
      mock.cipherWithIVBytes,
      mock.keys.privateKey,
      mock.keys.publicKey
    ),
    paramChecks: [
      {
        desc: 'correctly passes params with AES-CTR',
        req: () => ecc.decrypt(
          mock.cipherWithIVBytes,
          mock.keys.privateKey,
          mock.keys.publicKey
        ),
        params: (params: any) => (
          params[0].name === 'AES-CTR'
          && params[0].length === 64
          && arrBufEq(params[0].counter.buffer, mock.iv)
          && params[1] === mock.symmKey
          && arrBufEq(params[2], mock.cipherBytes)
        )
      },
      {
        desc: 'correctly passes params with AES-CBC',
        req: () => ecc.decrypt(
          mock.cipherWithIVBytes,
          mock.keys.privateKey,
          mock.keys.publicKey,
          DEFAULT_ECC_CURVE,
          { alg: SymmAlg.AES_CBC }
        ),
        params: (params: any) => (
          params[0]?.name === 'AES-CBC'
          && arrBufEq(params[0].iv, mock.iv)
          && arrBufEq(params[2], mock.cipherBytes)
        )
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'decrypt',
    setMock: fake => {
      webcrypto.decrypt = fake
      webcrypto.deriveKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
    },
    mockResp: mock.msgBytes,
    simpleReq: () => ecc.decrypt(
      mock.cipherWithIVStr,
      mock.keys.privateKey,
      mock.keyBase64,
      DEFAULT_ECC_CURVE
    ),
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getPublicKey',
    setMock: fake => webcrypto.exportKey = fake,
    mockResp: utils.base64ToArrBuf(mock.keyBase64),
    expectedResp: mock.keyBase64,
    simpleReq: () => ecc.getPublicKey(mock.keys),
    simpleParams: [
      'raw',
      mock.keys.publicKey
    ],
    paramChecks: [],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getSharedKey',
    setMock: fake => webcrypto.deriveKey = fake,
    mockResp: mock.symmKey,
    simpleReq: () => ecc.getSharedKey(mock.keys.privateKey, mock.keys.publicKey),
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
        req: () => ecc.getSharedKey(mock.keys.privateKey, mock.keys.publicKey, { alg: SymmAlg.AES_CBC }),
        params: (params: any) => params[2]?.name === 'AES-CBC'
      },
      {
        desc: 'handles multiple symm key lengths',
        req: () => ecc.getSharedKey(mock.keys.privateKey, mock.keys.publicKey, { length: SymmKeyLength.B256 }),
        params: (params: any) => params[2]?.length === 256
      }
    ],
    shouldThrows: []
  })

})

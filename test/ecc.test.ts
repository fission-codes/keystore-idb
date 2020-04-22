import ecc from '../src/ecc'
import errors from '../src/errors'
import utils from '../src/utils'
import { KeyUse, EccCurve, HashAlg, SymmAlg, SymmKeyLength } from '../src/types'
import { mock, cryptoMethod, arrBufEq } from './utils'

describe('ecc', () => {

  cryptoMethod({
    desc: 'makeKeypair',
    setMock: fake => window.crypto.subtle.generateKey = fake,
    mockResp: mock.keys,
    simpleReq: () => ecc.makeKeypair(EccCurve.P_256, KeyUse.Read),
    simpleParams: [
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
        [ 'deriveKey', 'deriveBits']
    ],
    paramChecks: [
      {
        desc: 'handles multiple key algorithms',
        req: () => ecc.makeKeypair(EccCurve.P_521, KeyUse.Read),
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
    desc: 'importPublicReadKey',
    setMock: fake => window.crypto.subtle.importKey = fake,
    mockResp: mock.keys.publicKey,
    expectedResp: mock.keys.publicKey,
    simpleReq: () => ecc.importPublicKey(mock.keyBase64, EccCurve.P_256, KeyUse.Read),
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
        req: () => ecc.importPublicKey(mock.keyBase64, EccCurve.P_521, KeyUse.Read),
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
    desc: 'signBytes',
    setMock: fake => window.crypto.subtle.sign = fake,
    mockResp: mock.sigBytes,
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
    simpleReq: () => ecc.verifyBytes(mock.msgBytes, mock.sigBytes, mock.keys.publicKey, HashAlg.SHA_256),
    simpleParams: [
      { name: 'ECDSA', hash: {name: 'SHA-256' }},
      mock.keys.publicKey,
      mock.sigBytes,
      mock.msgBytes
    ],
    paramChecks: [
      {
        desc: 'handles multiple hash algorithms',
        req: () => ecc.verifyBytes(mock.msgBytes, mock.sigBytes, mock.keys.publicKey, HashAlg.SHA_512),
        params: (params: any) => params[0]?.hash?.name === 'SHA-512'
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getSharedKey',
    setMock: fake => window.crypto.subtle.deriveKey = fake,
    mockResp: mock.symmKey,
    simpleReq: () => ecc.getSharedKey(mock.keys.privateKey, mock.keys.publicKey),
    simpleParams: [
      { name: 'ECDH', public: mock.keys.publicKey },
      mock.keys.privateKey,
      { name: 'AES-CTR', length: 128 },
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


  cryptoMethod({
    desc: 'encryptBytes',
    setMock: fake => {
      window.crypto.subtle.encrypt = fake
      window.crypto.subtle.deriveKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
      window.crypto.getRandomValues = jest.fn(() => new Promise(r => r(new Uint8Array(16)))) as any
    },
    mockResp: mock.cipherBytes,
    simpleReq: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey),
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
        req: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, { alg: SymmAlg.AES_CBC }),
        params: (params: any) => params[0]?.name === 'AES-CBC'
      },
      {
        desc: 'handles multiple symm key lengths',
        req: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, { length: SymmKeyLength.B256 }),
        params: (params: any) => params[0]?.length === 256
      },
      {
        desc: 'handles an IV with AES-CTR',
        req: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, { iv: mock.iv }),
        params: (params: any) => arrBufEq(params[0]?.counter, mock.iv)
      },
      {
        desc: 'handles an IV with AES-CBC',
        req: () => ecc.encryptBytes(mock.msgBytes, mock.keys.privateKey, mock.keys.publicKey, { alg: SymmAlg.AES_CBC, iv: mock.iv }),
        params: (params: any) => params[0]?.iv === mock.iv
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'decryptBytes',
    setMock: fake => {
      window.crypto.subtle.decrypt = fake
      window.crypto.subtle.deriveKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
    },
    mockResp: mock.msgBytes,
    simpleReq: () => ecc.decryptBytes(mock.cipherWithIVBytes, mock.keys.privateKey, mock.keys.publicKey),
    paramChecks: [
      {
        desc: 'correctly passes params with AES-CTR',
        req: () => ecc.decryptBytes(mock.cipherWithIVBytes, mock.keys.privateKey, mock.keys.publicKey),
        params: (params: any) => (
          params[0].name === 'AES-CTR'
          && params[0].length === 128 
          && arrBufEq(params[0].counter.buffer, mock.iv)
          && params[1] === mock.symmKey 
          && arrBufEq(params[2], mock.cipherBytes)
        )
      },
      {
        desc: 'correctly passes params with AES-CBC',
        req: () => ecc.decryptBytes(mock.cipherWithIVBytes, mock.keys.privateKey, mock.keys.publicKey, { alg: SymmAlg.AES_CBC }),
        params: (params: any) => (
          params[0]?.name === 'AES-CBC'
          && arrBufEq(params[0].iv, mock.iv)
          && arrBufEq(params[2], mock.cipherBytes)
        )
      },
      {
        desc: 'handles multiple symm key lengths',
        req: () => ecc.decryptBytes(mock.cipherWithIVBytes, mock.keys.privateKey, mock.keys.publicKey, { length: SymmKeyLength.B256 }),
        params: (params: any) => params[0]?.length === 256
      },
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'getPublicKey',
    setMock: fake => window.crypto.subtle.exportKey = fake,
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

})

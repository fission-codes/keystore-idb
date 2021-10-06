import aes from '../src/aes'
import utils from '../src/utils'
import { SymmAlg, SymmKeyLength } from '../src/types'
import { crypto, webcrypto } from '../src/webcrypto'
import { mock, cryptoMethod, arrBufEq } from './utils'

describe('aes', () => {

  cryptoMethod({
    desc: 'makeKey',
    setMock: fake => webcrypto.generateKey = fake,
    mockResp: mock.symmKey,
    simpleReq: () => aes.makeKey(),
    simpleParams: [
      { name: 'AES-CTR', length: 256 },
      true,
      [ 'encrypt', 'decrypt']
    ],
    paramChecks: [
      {
        desc: 'handles multiple key algorithms',
        req: () => aes.makeKey({ alg: SymmAlg.AES_CBC }),
        params: (params: any) => params[0]?.name === 'AES-CBC'
      },
      {
        desc: 'handles multiple key algorithms',
        req: () => aes.makeKey({ alg: SymmAlg.AES_GCM }),
        params: (params: any) => params[0]?.name === 'AES-GCM'
      },
      {
        desc: 'handles multiple key lengths',
        req: () => aes.makeKey({ length: SymmKeyLength.B256 }),
        params: (params: any) => params[0]?.length === 256
      }
    ],
    shouldThrows: [ ]
  })


  cryptoMethod({
    desc: 'importKey',
    setMock: fake => webcrypto.importKey = fake,
    mockResp: mock.symmKey,
    simpleReq: () => aes.importKey(mock.keyBase64),
    simpleParams: [
      'raw',
      utils.base64ToArrBuf(mock.keyBase64),
      { name: 'AES-CTR', length: 256 },
      true,
      [ 'encrypt', 'decrypt']
    ],
    paramChecks: [
      {
        desc: 'handles multiple key algorithms',
        req: () => aes.importKey(mock.keyBase64, { alg: SymmAlg.AES_CBC }),
        params: (params: any) => params[2]?.name === 'AES-CBC'
      },
      {
        desc: 'handles multiple key lengths',
        req: () => aes.importKey(mock.keyBase64, { length: SymmKeyLength.B256 }),
        params: (params: any) => params[2]?.length === 256
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'encrypt',
    setMock: fake => {
      webcrypto.encrypt = fake
      webcrypto.importKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
      crypto.getRandomValues = jest.fn(() => new Promise(r => r(new Uint8Array(16)))) as any
    },
    mockResp: mock.cipherBytes,
    expectedResp: mock.cipherWithIVStr,
    simpleReq: () => aes.encrypt(mock.msgStr, mock.keyBase64, { iv: mock.iv }),
    paramChecks: [
      {
        desc: 'correctly passes params with AES-CTR',
        req: () => aes.encrypt(mock.msgStr, mock.keyBase64, { iv: mock.iv }),
        params: (params: any) => (
          params[0]?.name === 'AES-CTR'
          && params[0]?.length === 64
          && arrBufEq(params[0]?.counter, mock.iv)
          && params[1] === mock.symmKey
          && arrBufEq(params[2], mock.msgBytes)
        )
      },
      {
        desc: 'correctly passes params with AES-CBC',
        req: () => aes.encrypt(mock.msgStr, mock.keyBase64, { alg: SymmAlg.AES_CBC, iv: mock.iv }),
        params: (params: any) => (
          params[0]?.name === 'AES-CBC'
          && arrBufEq(params[0]?.iv, mock.iv)
          && params[1] === mock.symmKey
          && arrBufEq(params[2], mock.msgBytes)
        )
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'decrypt',
    setMock: fake => {
      webcrypto.decrypt = fake
      webcrypto.importKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
    },
    mockResp: mock.msgBytes,
    expectedResp: mock.msgStr,
    simpleReq: () => aes.decrypt(mock.cipherWithIVStr, mock.keyBase64),
    paramChecks: [
      {
        desc: 'correctly passes params with AES-CTR',
        req: () => aes.decrypt(mock.cipherWithIVStr, mock.keyBase64),
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
        req: () => aes.decrypt(mock.cipherWithIVStr, mock.keyBase64, { alg: SymmAlg.AES_CBC }),
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
    desc: 'exportKey',
    setMock: fake => webcrypto.exportKey = fake,
    mockResp: utils.base64ToArrBuf(mock.keyBase64),
    expectedResp: mock.keyBase64,
    simpleReq: () => aes.exportKey(mock.symmKey),
    simpleParams: [
      'raw',
      mock.symmKey
    ],
    paramChecks: [],
    shouldThrows: []
  })


})

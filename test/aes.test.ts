import { webcrypto } from 'one-webcrypto'
import aes from '../src/aes'
import * as common from '../src/common'
import utils from '../src/utils'
import { ExportKeyFormat, SymmAlg, SymmKeyLength } from '../src/types'
import { mock, cryptoMethod, arrBufEq } from './utils'

describe('aes', () => {

  cryptoMethod({
    desc: 'genKey',
    setMock: fake => webcrypto.subtle.generateKey = fake,
    mockResp: mock.symmKey,
    simpleReq: () => aes.genKey(),
    simpleParams: [
      { name: 'AES-GCM', length: 256 },
      true,
      [ 'encrypt', 'decrypt']
    ],
    paramChecks: [
      {
        desc: 'handles only AES-GCM',
        req: () => aes.genKey({ alg: SymmAlg.AES_GCM }),
        params: (params: any) => params[0]?.name === 'AES-GCM'
      }
    ],
    shouldThrows: [ ]
  })

  cryptoMethod({
    desc: 'importKey',
    setMock: fake => webcrypto.subtle.importKey = fake,
    mockResp: mock.symmKey,
    simpleReq: () => aes.importKey(mock.keyBase64),
    simpleParams: [
      ExportKeyFormat.RAW,
      utils.base64ToArrBuf(mock.keyBase64),
      { name: 'AES-GCM', length: 256 },
      false,
      [ 'encrypt', 'decrypt']
    ],
    paramChecks: [
      {
        desc: 'handles only AES-GCM',
        req: () => aes.importKey(mock.keyBase64, { alg: SymmAlg.AES_GCM }),
        params: (params: any) => params[2]?.name === 'AES-GCM'
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
      webcrypto.subtle.encrypt = fake
      webcrypto.subtle.importKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
      webcrypto.getRandomValues = jest.fn(() => new Promise(r => r(new Uint8Array(16)))) as any
    },
    mockResp: mock.cipherBytes,
    expectedResp: mock.cipherWithIVStr,
    simpleReq: () => aes.importKey(mock.keyBase64).then(key => aes.encrypt(mock.msgStr, key, { iv: mock.iv })),
    paramChecks: [
      {
        desc: 'correctly passes params with AES-GCM',
        req: () => aes.importKey(mock.keyBase64).then(key => aes.encrypt(mock.msgStr, key, { iv: mock.iv })),
        params: (params: any) => (
          params[0]?.name === 'AES-GCM'
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
      webcrypto.subtle.decrypt = fake
      webcrypto.subtle.importKey = jest.fn(() => new Promise(r => r(mock.symmKey)))
    },
    mockResp: mock.msgBytes,
    expectedResp: mock.msgStr,
    simpleReq: () => aes.importKey(mock.keyBase64).then(key => aes.decrypt(mock.cipherWithIVStr, key)),
    paramChecks: [
      {
        desc: 'correctly passes params with AES-GCM',
        req: () => aes.importKey(mock.keyBase64).then(key => aes.decrypt(mock.cipherWithIVStr, key)),
        params: (params: any) => (
          params[0].name === 'AES-GCM'
          && arrBufEq(params[0].iv, mock.iv)
          && params[1] === mock.symmKey
          && arrBufEq(params[2], mock.cipherBytes)
        )
      }
    ],
    shouldThrows: []
  })

  cryptoMethod({
    desc: 'exportKey',
    setMock: fake => webcrypto.subtle.exportKey = fake,
    mockResp: utils.base64ToArrBuf(mock.keyBase64),
    expectedResp: mock.keyBase64,
    simpleReq: () => common.exportKey(mock.symmKey, ExportKeyFormat.RAW),
    simpleParams: [
      ExportKeyFormat.RAW,
      mock.symmKey
    ],
    paramChecks: [],
    shouldThrows: []
  })
})

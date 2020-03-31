import aes from '../src/aes'
import utils from '../src/utils'
import { SymmAlg, SymmKeyLength } from '../src/types'
import { mock, cryptoMethod, idbMethod, arrBufEq } from './utils'

const sinon = require('sinon')

describe('aes', () => {

  beforeEach(() => sinon.restore())

  cryptoMethod({
    desc: 'makeKey',
    setMock: fake => window.crypto.subtle.generateKey = fake,
    mockResp: mock.symmKey,
    simpleReq: () => aes.makeKey(),
    simpleParams: [
      { name: 'AES-CTR', length: 128 },
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
        desc: 'handles multiple key lengths',
        req: () => aes.makeKey({ length: SymmKeyLength.B256 }),
        params: (params: any) => params[0]?.length === 256
      }
    ],
    shouldThrows: [ ]
  })


  describe('getKey', () => {
    idbMethod({
      desc: 'key does not exist',
      req: () => aes.getKey(mock.symmKeyName),
      expectedResponse: mock.symmKey,
      fakeMakeResp: mock.symmKey,
      putParams: [
        mock.symmKeyName,
        mock.symmKey
      ],
      getParams: [
        mock.symmKeyName
      ],
      makeParams: [
        {
          name: 'AES-CTR',
          length: 128
        },
        true,
        ['encrypt', 'decrypt']
      ],
      putCount: 1,
      getCount: 1,
      makeCount: 1,
    })

    idbMethod({
      desc: 'key does exist',
      req: () => aes.getKey(mock.symmKeyName),
      expectedResponse: mock.symmKey,
      fakeGetResp: mock.symmKey,
      getParams: [
        mock.symmKeyName
      ],
      putCount: 0,
      getCount: 1,
      makeCount: 0,
    })
  })


  cryptoMethod({
    desc: 'importKey',
    setMock: fake => window.crypto.subtle.importKey = fake,
    mockResp: mock.symmKey,
    simpleReq: () => aes.importKey(mock.keyBase64),
    simpleParams: [
      'raw',
      utils.base64ToArrBuf(mock.keyBase64),
      { name: 'AES-CTR', length: 128 },
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
      window.crypto.subtle.encrypt = fake
      window.crypto.subtle.importKey = sinon.fake.returns(new Promise(r => r(mock.symmKey)))
      window.crypto.getRandomValues = sinon.fake.returns(new Promise(r => r()))
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
          && params[0]?.length === 128
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
          && params[0]?.length === 128
          && arrBufEq(params[0]?.iv, mock.iv)
          && params[1] === mock.symmKey
          && arrBufEq(params[2], mock.msgBytes)
        )
      },
      {
        desc: 'handles multiple symm key lengths',
        req: () => aes.encrypt(mock.msgStr, mock.keyBase64, { length: SymmKeyLength.B256}),
        params: (params: any) => params[0]?.length === 256
      }
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'decrypt',
    setMock: fake => {
      window.crypto.subtle.decrypt = fake
      window.crypto.subtle.importKey = sinon.fake.returns(new Promise(r => r(mock.symmKey)))
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
          && params[0].length === 128 
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
      },
      {
        desc: 'handles multiple symm key lengths',
        req: () => aes.decrypt(mock.cipherWithIVStr, mock.keyBase64, { length: SymmKeyLength.B256 }),
        params: (params: any) => params[0]?.length === 256
      },
    ],
    shouldThrows: []
  })


  cryptoMethod({
    desc: 'exportKey',
    setMock: fake => window.crypto.subtle.exportKey = fake,
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

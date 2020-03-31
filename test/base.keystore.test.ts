import aes from '../src/aes'
import idb from '../src/idb'
import config from '../src/config'
import { mock, keystoreMethod } from './utils'

const defaultOpts = { alg: config.defaultConfig.symmAlg, length: config.defaultConfig.symmLen }

describe("KeyStoreBase", () => {

  keystoreMethod({
    desc: 'keyExists',
    type: 'rsa',
    mocks: [
      {
        mod: idb,
        meth: 'exists', 
        resp: true,
        params: [
          mock.symmKeyName
        ]
      },
    ],
    reqFn: (ks) => ks.keyExists(mock.symmKeyName),
    expectedResp: true,
  })


  keystoreMethod({
    desc: 'importSymmKey',
    type: 'rsa',
    mocks: [
      {
        mod: aes,
        meth: 'importKey', 
        resp: mock.symmKey,
        params: [
          mock.keyBase64,
          defaultOpts
        ]
      },
      {
        mod: idb,
        meth: 'putKey', 
        resp: undefined,
        params: [
          mock.symmKeyName,
          mock.symmKey
        ]
      }
    ],
    reqFn: (ks) => ks.importSymmKey(mock.keyBase64, mock.symmKeyName),
  })


  keystoreMethod({
    desc: 'exportSymmKey',
    type: 'rsa',
    mocks: [
      {
        mod: aes,
        meth: 'getKey', 
        resp: mock.symmKey,
        params: [
          mock.symmKeyName,
          defaultOpts
        ]
      },
      {
        mod: aes,
        meth: 'exportKey', 
        resp: mock.keyBase64,
        params: [
          mock.symmKey
        ]
      }
    ],
    reqFn: (ks) => ks.exportSymmKey(mock.symmKeyName),
    expectedResp: mock.keyBase64
  })


  keystoreMethod({
    desc: 'encryptWithSymmKey',
    type: 'rsa',
    mocks: [
      {
        mod: aes,
        meth: 'getKey', 
        resp: mock.symmKey,
        params: [
          mock.symmKeyName,
          defaultOpts
        ]
      },
      {
        mod: aes,
        meth: 'encryptBytes', 
        resp: mock.cipherBytes,
        params: [
          mock.msgBytes,
          mock.symmKey,
          defaultOpts
        ]
      }
    ],
    reqFn: (ks) => ks.encryptWithSymmKey(mock.msgStr, mock.symmKeyName),
    expectedResp: mock.cipherStr
  })


  keystoreMethod({
    desc: 'decryptWithSymmKey',
    type: 'rsa',
    mocks: [
      {
        mod: aes,
        meth: 'getKey', 
        resp: mock.symmKey,
        params: [
          mock.symmKeyName,
          defaultOpts
        ]
      },
      {
        mod: aes,
        meth: 'decryptBytes', 
        resp: mock.msgBytes,
        params: [
          mock.cipherBytes,
          mock.symmKey,
          defaultOpts
        ]
      }
    ],
    reqFn: (ks) => ks.decryptWithSymmKey(mock.cipherStr, mock.symmKeyName),
    expectedResp: mock.msgStr
  })

})

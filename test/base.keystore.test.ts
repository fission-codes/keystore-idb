import aes from '../src/aes'
import idb from '../src/idb'
import config from '../src/config'
import { mock, keystoreMethod } from './utils'

const defaultOpts = { alg: config.defaultConfig.symmAlg, length: config.defaultConfig.symmKeyLength }

describe("KeyStoreBase", () => {

  keystoreMethod({
    desc: 'keyExists',
    mocks: [
      {
        mod: idb,
        meth: 'getKey', 
        resp: null,
        params: [
          mock.symmKeyName,
          mock.idbStore
        ]
      },
    ],
    reqFn: (ks) => ks.keyExists(mock.symmKeyName),
    expectedResp: false,
  })


  keystoreMethod({
    desc: 'getSymmKey (exists)',
    mocks: [
      {
        mod: idb,
        meth: 'getKey', 
        resp: mock.symmKey,
        params: [
          mock.symmKeyName,
          mock.idbStore
        ]
      },
    ],
    reqFn: (ks) => ks.getSymmKey(mock.symmKeyName),
    expectedResp: mock.symmKey,
  })

  keystoreMethod({
    desc: 'getSymmKey (does not exist)',
    mocks: [
      {
        mod: idb,
        meth: 'getKey', 
        resp: null,
        params: [
          mock.symmKeyName,
          mock.idbStore
        ]
      },
            {
        mod: aes,
        meth: 'makeKey', 
        resp: mock.symmKey,
        params: [
          config.symmKeyOpts(config.defaultConfig)
        ]
      },
      {
        mod: idb,
        meth: 'put', 
        resp: null,
        params: [
          mock.symmKeyName,
          mock.symmKey,
          mock.idbStore
        ]
      },

    ],
    reqFn: (ks) => ks.getSymmKey(mock.symmKeyName),
    expectedResp: mock.symmKey,
  })


  keystoreMethod({
    desc: 'importSymmKey',
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
        meth: 'put', 
        resp: undefined,
        params: [
          mock.symmKeyName,
          mock.symmKey,
          mock.idbStore
        ]
      }
    ],
    reqFn: (ks) => ks.importSymmKey(mock.keyBase64, mock.symmKeyName),
  })


  keystoreMethod({
    desc: 'exportSymmKey',
    mocks: [
      {
        mod: idb,
        meth: 'getKey', 
        resp: mock.symmKey,
        params: [
          mock.symmKeyName,
          mock.idbStore
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
    mocks: [
      {
        mod: idb,
        meth: 'getKey', 
        resp: mock.symmKey,
        params: [
          mock.symmKeyName,
          mock.idbStore
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
    mocks: [
      {
        mod: idb,
        meth: 'getKey', 
        resp: mock.symmKey,
        params: [
          mock.symmKeyName,
          mock.idbStore
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


  keystoreMethod({
    desc: 'deleteKey',
    mocks: [
      {
        mod: idb,
        meth: 'rm', 
        resp: undefined,
        params: [
          mock.symmKeyName,
          mock.idbStore
        ]
      }
    ],
    reqFn: (ks) => ks.deleteKey(mock.symmKeyName),
    expectedResp: undefined
  })

  keystoreMethod({
    desc: 'clear',
    mocks: [
      {
        mod: idb,
        meth: 'clear', 
        resp: undefined,
        params: [
          mock.idbStore
        ]
      }
    ],
    reqFn: (ks) => ks.clear(),
    expectedResp: undefined
  })

})

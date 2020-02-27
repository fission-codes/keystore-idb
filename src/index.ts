import { init, clear } from './keystore'

import * as ecc from './ecc'
import * as rsa from './rsa'
import * as config from './config'
import * as constants from './constants'
import * as utils from './utils'
import * as idb from './idb'
import * as types from './types'

export default {
  init,
  clear,
  ecc,
  rsa,
  config,
  constants,
  utils,
  idb,
  types,
}

// const run = async () => {
//   const ALG = 'rsa'
//   await clear()
//   const ks1 = await init({ type: ALG, readKeyName: 'read-key-1', writeKeyName: 'write-key-1' })
//   const ks2 = await init({ type: ALG, readKeyName: 'read-key-2', writeKeyName: 'write-key-2' })

//   const msg = "Incididunt id ullamco et do."
//   const readKey1 = await ks1.publicReadKey()
//   const readKey2 = await ks2.publicReadKey()
//   const writeKey1 = await ks1.publicWriteKey()

//   const sig = await ks1.sign(msg)
//   const valid = await ks2.verify(msg, sig, writeKey1)
//   console.log('sig: ', sig)
//   console.log('valid: ', valid)

//   const cipher = await ks1.encrypt(msg, readKey2)
//   const decipher = await ks2.decrypt(cipher, readKey1)
//   console.log('cipher: ', cipher)
//   console.log('decipher: ', decipher)
// }

// run()

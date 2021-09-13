import "@ungap/global-this"
import { init, clear } from './keystore/index.js'

import * as ecc from './ecc/index.js'
import * as rsa from './rsa/index.js'
import * as config from './config.js'
import * as constants from './constants.js'
import * as utils from './utils.js'
import * as idb from './idb.js'
import * as types from './types.js'

export default {
  init,
  clear,
  ...types,
  ...constants,
  ...config,
  ...utils,
  ecc,
  rsa,
  idb,
}

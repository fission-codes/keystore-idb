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
  ...types,
  ...constants,
  ...config,
  ...utils,
  ecc,
  rsa,
  idb,
}

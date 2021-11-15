import { webcrypto } from 'one-webcrypto'
import * as uint8arrays from "uint8arrays"

import { DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants.js'
import { SymmKey, SymmKeyOpts } from '../types.js'

export async function makeKey(opts?: Partial<SymmKeyOpts>): Promise<SymmKey> {
  return webcrypto.subtle.generateKey(
    {
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    true,
    ['encrypt', 'decrypt']
  )
}

export async function importKey(base64key: string, opts?: Partial<SymmKeyOpts>): Promise<SymmKey> {
  const buf = uint8arrays.fromString(base64key, "base64pad")
  return webcrypto.subtle.importKey(
    'raw',
    buf,
    {
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    true,
    ['encrypt', 'decrypt']
  )
}

export default {
  makeKey,
  importKey,
}

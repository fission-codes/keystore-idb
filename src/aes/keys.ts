import utils from '../utils'
import { DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants'
import { SymmKey, SymmKeyOpts } from '../types'

export async function makeKey(opts?: Partial<SymmKeyOpts>): Promise<SymmKey> {
  return window.crypto.subtle.generateKey(
    { 
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    true,
    ['encrypt', 'decrypt']
  )
}

export async function importKey(base64key: string, opts?: Partial<SymmKeyOpts>): Promise<SymmKey> {
  const buf = utils.base64ToArrBuf(base64key)
  return window.crypto.subtle.importKey(
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

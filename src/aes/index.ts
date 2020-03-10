import utils from '../utils'
import { DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants'
import { SymmKey, SymmKeyOpts, SymmAlg, CipherText } from '../types'

export async function encrypt(data: ArrayBuffer, key: SymmKey, opts?: Partial<SymmKeyOpts>): Promise<CipherText> {
  const alg = opts?.alg || DEFAULT_SYMM_ALG
  const iv = opts?.iv || utils.randomBuf(16)
  const cipherBuf = await window.crypto.subtle.encrypt(
    { 
      name: alg,
      length: opts?.length || DEFAULT_SYMM_LEN,
      // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
      iv: alg === SymmAlg.AES_CTR ? undefined : iv,
      counter: alg === SymmAlg.AES_CTR ? new Uint8Array(iv) : undefined,
    },
    key,
    data
  )
  return utils.joinBufs(iv, cipherBuf)
}

export async function decrypt(cipherText: CipherText, key: SymmKey, opts?: Partial<SymmKeyOpts>): Promise<ArrayBuffer> {
  const alg = opts?.alg || DEFAULT_SYMM_ALG
  const iv = cipherText.slice(0, 16)
  const cipherBytes = cipherText.slice(16)
  const msgBuff = await window.crypto.subtle.decrypt(
    { name: alg,
      length: opts?.length || DEFAULT_SYMM_LEN,
      // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
      iv: alg === SymmAlg.AES_CTR ? undefined : iv,
      counter: alg === SymmAlg.AES_CTR ? new Uint8Array(iv) : undefined,
    },
    key,
    cipherBytes
  )
  return msgBuff
}

export default {
  decrypt,
  encrypt
}

import keys from './keys'
import utils from './utils'
import { DEFAULT_SYMM_ALG } from './constants'

export async function getSharedKey(publicKey: PublicKey): Promise<SymmKey> {
  const { privateKey } = await keys.getReadKey()
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: DEFAULT_SYMM_ALG, length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export async function encrypt(msg: string, publicKey: PublicKey): Promise<CipherText> {
  const cipherKey = await getSharedKey(publicKey)
  return crypto.subtle.encrypt(
    { name: DEFAULT_SYMM_ALG,
      counter: new Uint8Array(16),
      length: 128
    },
    cipherKey,
    utils.strToArrBuf(msg)
  )
}

export async function decrypt(cipherText: CipherText, publicKey: CryptoKey): Promise<string> {
  const cipherKey = await getSharedKey(publicKey)
  const msgBuff = await crypto.subtle.encrypt(
    { name: DEFAULT_SYMM_ALG,
      counter: new Uint8Array(16),
      length: 128
    },
    cipherKey,
    cipherText
  )
  return utils.arrBufToStr(msgBuff)
}

export default {
  encrypt,
  decrypt,
  getSharedKey,
}

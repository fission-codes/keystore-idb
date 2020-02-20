import keys from './keys'
import utils from './utils'
import { DEFAULT_SYMM_ALG, DEFAULT_HASH_ALG } from './constants'

export async function sign(msg: string) {
  const sigBytes = await signBytes(utils.strToArrBuf(msg))
  return utils.arrBufToHex(sigBytes)
}

export async function signBytes(data: ArrayBuffer): Promise<ArrayBuffer> {
  const { privateKey } = await keys.getWriteKey()
  return window.crypto.subtle.sign(
    { name: "ECDSA", hash: {name: DEFAULT_HASH_ALG}},
    privateKey,
    data
  )
}

export async function verify(msg: string, sig: string, publicKey: PublicKey): Promise<boolean> {
  return verifyBytes(
    utils.strToArrBuf(msg),
    utils.hexToArrBuf(sig),
    publicKey
  )
}

export async function verifyBytes(data: ArrayBuffer, sig: ArrayBuffer, publicKey: PublicKey): Promise<boolean> {
  return window.crypto.subtle.verify(
    { name: "ECDSA", hash: {name: DEFAULT_HASH_ALG}},
    publicKey,
    sig, 
    data 
  )
}

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

export async function encrypt(msg: string, publicKey: PublicKey): Promise<string> {
  const cipherText = await encryptBytes(utils.strToArrBuf(msg), publicKey)
  return utils.arrBufToHex(cipherText)
}

export async function encryptBytes(data: ArrayBuffer, publicKey: PublicKey): Promise<CipherText> {
  const cipherKey = await getSharedKey(publicKey)
  return crypto.subtle.encrypt(
    { name: DEFAULT_SYMM_ALG,
      counter: new Uint8Array(16),
      length: 128
    },
    cipherKey,
    data
  )
}

export async function decrypt(cipherText: string, publicKey: CryptoKey): Promise<string> {
  const msgBytes = await decryptBytes(utils.hexToArrBuf(cipherText), publicKey)
  return utils.arrBufToStr(msgBytes)
}

export async function decryptBytes(cipherText: CipherText, publicKey: CryptoKey): Promise<ArrayBuffer> {
  const cipherKey = await getSharedKey(publicKey)
  const msgBuff = await crypto.subtle.encrypt(
    { name: DEFAULT_SYMM_ALG,
      counter: new Uint8Array(16),
      length: 128
    },
    cipherKey,
    cipherText
  )
  return msgBuff
}

export default {
  sign,
  signBytes,
  verify,
  verifyBytes,
  encrypt,
  encryptBytes,
  decrypt,
  decryptBytes,
  getSharedKey,
}

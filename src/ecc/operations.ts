import utils from '../utils'
import { ECC_READ_ALG, ECC_WRITE_ALG } from '../constants'
import { PrivateKey, PublicKey, HashAlg, SymmAlg, SymmKey, CipherText } from '../types'

export async function signBytes(data: ArrayBuffer, privKey: PrivateKey, hashAlg: HashAlg): Promise<ArrayBuffer> {
  return window.crypto.subtle.sign(
    { name: ECC_WRITE_ALG, hash: {name: hashAlg }},
    privKey,
    data
  )
}

export async function verifyBytes(data: ArrayBuffer, sig: ArrayBuffer, publicKey: PublicKey, hashAlg: HashAlg): Promise<boolean> {
  return window.crypto.subtle.verify(
    { name: ECC_WRITE_ALG, hash: {name: hashAlg }},
    publicKey,
    sig, 
    data 
  )
}

export async function getSharedKey(privateKey: PrivateKey, publicKey: PublicKey, symmAlg: SymmAlg): Promise<SymmKey> {
  return window.crypto.subtle.deriveKey(
    { name: ECC_READ_ALG, public: publicKey },
    privateKey,
    { name: symmAlg, length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export async function encryptBytes(data: ArrayBuffer, privateKey: PrivateKey, publicKey: PublicKey, symmAlg: SymmAlg): Promise<CipherText> {
  const cipherKey = await getSharedKey(privateKey, publicKey, symmAlg)
  return window.crypto.subtle.encrypt(
    { name: symmAlg,
      counter: new Uint8Array(16),
      length: 128
    },
    cipherKey,
    data
  )
}

export async function decryptBytes(cipherText: CipherText, privateKey: PrivateKey, publicKey: PublicKey, symmAlg: SymmAlg): Promise<ArrayBuffer> {
  const cipherKey = await getSharedKey(privateKey, publicKey, symmAlg)
  const msgBuff = await window.crypto.subtle.decrypt(
    { name: symmAlg,
      counter: new Uint8Array(16),
      length: 128
    },
    cipherKey,
    cipherText
  )
  return msgBuff
}

export async function getPublicKey(keypair: CryptoKeyPair): Promise<string> {
  const raw = await window.crypto.subtle.exportKey('raw', keypair.publicKey)
  return utils.arrBufToHex(raw)
}

export default {
  signBytes,
  verifyBytes,
  getSharedKey,
  encryptBytes,
  decryptBytes,
  getPublicKey
}

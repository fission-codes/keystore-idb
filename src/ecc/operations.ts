import aes from '../aes'
import utils from '../utils'
import { ECC_READ_ALG, ECC_WRITE_ALG, DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants'
import { PrivateKey, PublicKey, HashAlg, SymmKey, SymmKeyOpts, CipherText } from '../types'

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

export async function getSharedKey(privateKey: PrivateKey, publicKey: PublicKey, opts?: Partial<SymmKeyOpts>): Promise<SymmKey> {
  return window.crypto.subtle.deriveKey(
    { name: ECC_READ_ALG, public: publicKey },
    privateKey,
    { 
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN
    },
    false,
    ['encrypt', 'decrypt']
  )
}

export async function encryptBytes(data: ArrayBuffer, privateKey: PrivateKey, publicKey: PublicKey, opts?: Partial<SymmKeyOpts>): Promise<CipherText> {
  const cipherKey = await getSharedKey(privateKey, publicKey, opts)
  return aes.encryptBytes(data, cipherKey, opts)
}

export async function decryptBytes(cipherText: CipherText, privateKey: PrivateKey, publicKey: PublicKey, opts?: Partial<SymmKeyOpts>): Promise<ArrayBuffer> {
  const cipherKey = await getSharedKey(privateKey, publicKey, opts)
  return aes.decryptBytes(cipherText, cipherKey, opts)
}

export async function getPublicKey(keypair: CryptoKeyPair): Promise<string> {
  const raw = await window.crypto.subtle.exportKey('raw', keypair.publicKey)
  return utils.arrBufToBase64(raw)
}

export default {
  signBytes,
  verifyBytes,
  getSharedKey,
  encryptBytes,
  decryptBytes,
  getPublicKey
}

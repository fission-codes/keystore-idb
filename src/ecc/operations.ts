import utils from '../utils'
import { ECC_READ_ALG, ECC_WRITE_ALG, DEFAULT_SYMM_ALG, DEFAULT_SYMM_LEN } from '../constants'
import { PrivateKey, PublicKey, HashAlg, SymmKey, SymmKeyOpts, SymmAlg, CipherText } from '../types'

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
    cipherKey,
    data
  )
  return utils.joinBufs(iv, cipherBuf)
}

export async function decryptBytes(cipherText: CipherText, privateKey: PrivateKey, publicKey: PublicKey, opts?: Partial<SymmKeyOpts>): Promise<ArrayBuffer> {
  const cipherKey = await getSharedKey(privateKey, publicKey, opts)
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
    cipherKey,
    cipherBytes
  )
  return msgBuff
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

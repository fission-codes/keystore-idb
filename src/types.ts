export type CipherText = ArrayBuffer
export type SymmKey = CryptoKey

export type PublicKey = CryptoKey
export type PrivateKey = CryptoKey

export interface Config {
  type: 'ecc' | 'rsa'
  curve: ECC_Curve
  rsaSize: RSA_Size
  symmAlg: 'AES-CTR' | 'AES-GCM' | 'AES-CBC'
  hashAlg: HashAlg
  readKeyName: string
  writeKeyName: string
}

export interface PartialConfig {
  type?: 'ecc' | 'rsa'
  curve?: ECC_Curve
  rsaSize?: RSA_Size
  symmAlg?: 'AES-CTR' | 'AES-GCM' | 'AES-CBC'
  hashAlg?: HashAlg
  readKeyName?: string
  writeKeyName?: string
}

export type ECC_Curve = 'P-256' | 'P-384' | 'P-521'
export type RSA_Size = 1024 | 2048 | 4096
export type SymmAlg = 'AES-CTR' | 'AES-GCM' | 'AES-CBC'
export type HashAlg = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
export type CharSize = 8 | 16

export enum KeyUse {
  Read = 'read',
  Write = 'write'
}

export interface KeyStore {
  cfg: Config
  readKey: CryptoKeyPair
  writeKey: CryptoKeyPair
  sign(msg: string, charSize?: CharSize): Promise<string>
  verify(
    msg: string,
    sig: string,
    publicKey: PublicKey,
    charSize?: CharSize
  ): Promise<boolean>
  encrypt(
    msg: string,
    publicKey: PublicKey,
    charSize?: CharSize
  ): Promise<string>
  decrypt(
    cipherText: string,
    publicKey: PublicKey,
    charSize?: CharSize
  ): Promise<String>
  publicReadKey(): Promise<string>
  publicWriteKey(): Promise<string>
}

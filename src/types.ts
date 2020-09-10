export type Msg = ArrayBuffer | string | Uint8Array

export type CipherText = ArrayBuffer
export type SymmKey = CryptoKey

export type PublicKey = CryptoKey
export type PrivateKey = CryptoKey

export type Config = {
  type: CryptoSystem
  curve: EccCurve
  rsaSize: RsaSize
  symmAlg: SymmAlg
  symmLen: SymmKeyLength
  hashAlg: HashAlg
  charSize: CharSize
  storeName: string
  readKeyName: string
  writeKeyName: string
}

export type SymmKeyOpts = {
  alg: SymmAlg
  length: SymmKeyLength
  iv: ArrayBuffer
}

export enum CryptoSystem {
  ECC = 'ecc',
  RSA = 'rsa',
}

export enum EccCurve {
  P_256 = 'P-256',
  P_384 = 'P-384',
  P_521 = 'P-521',
}

export enum RsaSize {
  B1024 = 1024,
  B2048 = 2048,
  B4096 = 4096
}

export enum SymmAlg {
  AES_CTR = 'AES-CTR',
  AES_CBC = 'AES-CBC',
}

export enum SymmKeyLength {
  B128 = 128,
  B192 = 192,
  B256 = 256,
}

export enum HashAlg {
  SHA_1 = 'SHA-1',
  SHA_256 = 'SHA-256',
  SHA_384 = 'SHA-384',
  SHA_512 = 'SHA-512',
}

export enum CharSize {
  B8 = 8,
  B16 = 16,
}

export enum KeyUse {
  Read = 'read',
  Write = 'write',
}

export interface KeyStore {
  cfg: Config

  readKey: () => Promise<CryptoKeyPair>
  writeKey: () => Promise<CryptoKeyPair>
  getSymmKey: (keyName: string, cfg?: Partial<Config>) => Promise<CryptoKey>
  keyExists(keyName: string): Promise<boolean>
  deleteKey(keyName: string): Promise<void>
  destroy(): Promise<void>

  // Symmetric

  importSymmKey(
    keyStr: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<void>

  exportSymmKey(
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<string>

  encryptWithSymmKey(
    msg: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<string>

  decryptWithSymmKey(
    cipherBytes: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<string>

  // Asymmetric

  sign(
    msg: string,
    cfg?: Partial<Config>
  ): Promise<string>

  verify(
    msg: string,
    sig: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<boolean>

  encrypt(
    msg: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string>

  decrypt(
    cipherText: string,
    publicKey?: string,
    cfg?: Partial<Config>
  ): Promise<string>

  publicReadKey(): Promise<string>
  publicWriteKey(): Promise<string>
}

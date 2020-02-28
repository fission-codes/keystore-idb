export type CipherText = ArrayBuffer
export type SymmKey = CryptoKey

export type PublicKey = CryptoKey
export type PrivateKey = CryptoKey

export interface Config {
  type: CryptoSystem
  curve: ECC_Curve
  rsaSize: RSA_Size
  symmAlg: SymmAlg
  hashAlg: HashAlg
  readKeyName: string
  writeKeyName: string
}

export interface PartialConfig {
  type?: CryptoSystem
  curve?: ECC_Curve
  rsaSize?: RSA_Size
  symmAlg?: SymmAlg
  hashAlg?: HashAlg
  readKeyName?: string
  writeKeyName?: string
}

export enum CryptoSystem {
  ECC = 'ecc',
  RSA = 'rsa',
}

export enum ECC_Curve {
  P_256 = 'P-256',
  P_384 = 'P-384',
  P_521 = 'P-521',
}

export enum RSA_Size { 
  B1024 = 1024,
  B2048 = 2048,
  B4096 = 4096
}

export enum SymmAlg { 
  AES_CTR = 'AES-CTR', 
  AES_GCM = 'AES-GCM', 
  AES_CBC = 'AES-CBC', 
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
  readKey: CryptoKeyPair
  writeKey: CryptoKeyPair
  sign(msg: string, charSize?: CharSize): Promise<string>
  verify(
    msg: string,
    sig: string,
    publicKey: string,
    charSize?: CharSize
  ): Promise<boolean>
  encrypt(
    msg: string,
    publicKey: string,
    charSize?: CharSize
  ): Promise<string>
  decrypt(
    cipherText: string,
    publicKey: string,
    charSize?: CharSize
  ): Promise<string>
  publicReadKey(): Promise<string>
  publicWriteKey(): Promise<string>
}

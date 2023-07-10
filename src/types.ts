export type Msg = ArrayBuffer | string | Uint8Array

export type CipherText = ArrayBuffer
export type SymmKey = CryptoKey
export type SymmWrappingKey = CryptoKey

export type PublicKey = CryptoKey
export type PrivateKey = CryptoKey

export type Config = {
  // Asymmetric Configuration
  exchangeAlg: string
  writeAlg: string
  curve: EccCurve

  // Symmetric Configuration
  symmAlg: SymmAlg
  symmWrappingAlg: SymmWrappingAlg
  symmKeyLength: SymmKeyLength
  saltLength: SaltLength
  
  // Hash Configuration
  hashAlg: HashAlg
  charSize: CharSize
  
  // Key Store Configuration
  storeName: string
  exchangeKeyPairName: string
  writeKeyPairName: string
  passKeyName: string
}

export type SymmKeyOpts = {
  alg: SymmAlg
  length: SymmKeyLength
  iv: ArrayBuffer
}

export type SymmWrappingKeyOpts = {
  alg: SymmWrappingAlg
  length: SymmKeyLength
}

export enum ExportKeyFormat {
  PKCS8 = 'pkcs8',
  SPKI = 'spki',
  RAW = 'raw',
}

export enum CryptoSystem {
  ECC = 'ecc',
  RSA = 'rsa',
}

export enum EccCurve {
  P_384 = 'P-384',
  P_521 = 'P-521',
}

export enum RsaSize {
  B3072 = 3072,
  B4096 = 4096
}

export enum SymmAlg {
  AES_GCM = 'AES-GCM',
}

export enum SymmWrappingAlg {
  AES_KW = 'AES-KW',
}

export enum SymmKeyLength {
  B256 = 256,
  B512 = 512,
}

export enum HashAlg {
  SHA_256 = 'SHA-256',
  SHA_384 = 'SHA-384',
  SHA_512 = 'SHA-512',
}

export enum SaltLength {
  B128 = 128,
}

export enum CharSize {
  B8 = 8,
  B16 = 16,
}

export enum KeyUse {
  Exchange = 'exchange',
  Write = 'write',
}

export interface KeyStoreInterface {
  cfg: Config

  /* Keystore Management */

  keyExists(keyName: string): Promise<boolean>
  keyPairExists(keyPairName: string): Promise<boolean>
  deleteKey(keyName: string): Promise<void>
  clear(): Promise<void>

  /* Asymmetric Keys -- defines the keystore */

  // Key Generation and Import
  genExchangeKeyPair(cfg?: Partial<Config>): Promise<void>
  genWriteKeyPair(cfg?: Partial<Config>): Promise<void>
  unwrapExhangeKeyPair(
    publicKeyStr: string,
    wrappedPrivateKeyStr: string,
    cfg?: Partial<Config>
  ): Promise<void>
  unwrapWriteKeyPair(
    publicKeyStr: string,
    wrappedPrivateKeyStr: string,
    cfg?: Partial<Config>
  ): Promise<void>

  // Getters and Exporters
  getExchangeKeyPair: () => Promise<CryptoKeyPair>
  getWriteKeyPair: () => Promise<CryptoKeyPair>
  wrapExchangeKeyPair: () => Promise<{ publicKey: string, wrappedPrivateKey: string }>
  wrapWriteKeyPair: () => Promise<{ publicKey: string, wrappedPrivateKey: string }>

  // Utilities
  publicExchangeKeyFingerprint(): Promise<string>
  publicWriteKeyFingerprint(): Promise<string>

  // Key Operations
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
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string>
  wrapKey(
    key: CryptoKey,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string>
  unwrapKey(
    wrappedKey: string,
    publicKey: string,
    keyParams: AlgorithmIdentifier,
    uses: KeyUsage[],
    cfg?: Partial<Config>
  ): Promise<CryptoKey>


  /* Pass Key -- used to wrap and recover assymmetric keys */

  // Key Generation and Import
  derivePassKey(
    seedphrase: string,
    saltStr?: string,
    cfg?: Partial<Config>
  ): Promise<string>

  /* Symmetric Keys */

  // Key Generation and Import
  genSymmKey(
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<void>
  importSymmKey(
    keyStr: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<void>
  deriveSymmKey(
    keyName: string,
    seedphrase: string,
    salt: ArrayBuffer,
    cfg?: Partial<Config>
  ): Promise<void>

  // Getters and Exporters
  getSymmKey(keyName: string): Promise<CryptoKey>
  exportSymmKey(
    keyName: string,
  ): Promise<string>
  
  // Key Operations
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
}

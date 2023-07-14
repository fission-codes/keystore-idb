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
  symmKeyLength: SymmKeyLength
  // derivedBitLength: DerivedBitLength
  
  // Hash Configuration
  hashAlg: HashAlg
  charSize: CharSize
  
  // Key Store Configuration
  storeName: string
  exchangeKeyPairName: string
  writeKeyPairName: string
  escrowKeyName: string
}

export type EscrowedKeyPair = {
  publicKeyStr: string
  wrappedPrivateKeyStr: string
}

export type SymmKeyOpts = {
  alg: SymmAlg
  length: SymmKeyLength
  iv: ArrayBuffer
}

export enum ExportKeyFormat {
  PKCS8 = 'pkcs8',
  SPKI = 'spki',
  RAW = 'raw',
}

export enum CryptoSystem {
  ECC = 'ecc',
}

export enum EccCurve {
  P_384 = 'P-384',
}

export enum SymmAlg {
  AES_GCM = 'AES-GCM',
  AES_KW = 'AES-KW',
}

export enum SymmKeyLength {
  B256 = 256,
  B384 = 384,
  B512 = 512,
}

export enum HashAlg {
  SHA_256 = 'SHA-256',
  SHA_384 = 'SHA-384',
  SHA_512 = 'SHA-512',
}

export enum CharSize {
  B8 = 8,
  B16 = 16,
}

export enum KeyUse {
  Exchange = 'exchange',
  Write = 'write',
}

export interface KeyStore {
  cfg: Config

  /* Keystore Management */

  keyExists(keyName: string): Promise<boolean>
  keyPairExists(keyPairName: string): Promise<boolean>
  deleteKey(keyName: string): Promise<void>
  destroy(): Promise<void>

  /* Asymmetric Keys -- defines the keystore */

  // Getters and Exporters
  getExchangeKeyPair: () => Promise<CryptoKeyPair>
  getWriteKeyPair: () => Promise<CryptoKeyPair>

  /* Escrow Key -- used to wrap and recover assymmetric keys */

  deriveEscrowKey(
    passphrase: string,
    saltStr?: string,
    cfg?: Partial<Config>
  ): Promise<string>

  /* Symmetric Keys */

  // Key Generation and Import
  genSymmKey(
    keyName: string,
    uses: KeyUsage[],
    cfg?: Partial<Config>
  ): Promise<void>
  importSymmKey(
    keyStr: string,
    keyName: string,
    uses: KeyUsage[],
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
    cipherText: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<string>
  wrapKeyWithSymmKey(
    keyToWrap: CryptoKey,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<CipherText>
  unwrapKeyWithSymmKey(
    wrappedKey: CipherText,
    keyName: string,
    keyParams: AlgorithmIdentifier,
    extractable: boolean,
    uses: KeyUsage[],
    cfg?: Partial<Config>
  ): Promise<CryptoKey>
}

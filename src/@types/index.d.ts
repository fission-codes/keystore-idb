type CipherText = ArrayBuffer
type SymmKey = CryptoKey

type PublicKey = CryptoKey
type PrivateKey = CryptoKey

type EcdhKeyPair = CryptoKeyPair
type EcdsaKeyPair = CryptoKeyPair

// type RsaPublicKey = CryptoKey
type RsaReadKeyPair = CryptoKeyPair
type RsaWriteKeyPair = CryptoKeyPair

interface Config {
  type: 'ecc' | 'rsa'
  curve: ECC_Curve
  rsaSize: RSA_Size
  symmAlg: 'AES-CTR' | 'AES-GCM' | 'AES-CBC'
  hashAlg: HashAlg
  readKeyName: string
  writeKeyName: string
}

interface PartialConfig {
  type?: 'ecc' | 'rsa'
  curve?: ECC_Curve
  rsaSize?: RSA_Size
  symmAlg?: 'AES-CTR' | 'AES-GCM' | 'AES-CBC'
  hashAlg?: HashAlg
  readKeyName?: string
  writeKeyName?: string
}

type ECC_Curve = 'P-256' | 'P-384' | 'P-521'
type RSA_Size = 1024 | 2048 | 4096
type SymmAlg = 'AES-CTR' | 'AES-GCM' | 'AES-CBC'
type HashAlg = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'

interface KeyStore {
  cfg: Config
  readKey: CryptoKeyPair
  writeKey: CryptoKeyPair
  sign(msg: string): Promise<string>
  verify(msg: string, sig: string, publicKey: PublicKey): Promise<boolean>
  encrypt(msg: string, publicKey: PublicKey): Promise<string>
  decrypt(cipherText: string, publicKey: PublicKey): Promise<String>
  publicReadKey(): Promise<string>
  publicWriteKey(): Promise<string>
}

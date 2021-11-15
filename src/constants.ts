import { EccCurve, RsaSize, SymmAlg, SymmKeyLength, HashAlg } from './types.js'

export const ECC_EXCHANGE_ALG = 'ECDH'
export const ECC_WRITE_ALG = 'ECDSA'
export const RSA_EXCHANGE_ALG = 'RSA-OAEP'
export const RSA_WRITE_ALG = 'RSASSA-PKCS1-v1_5'
export const SALT_LENGTH = 128

export const DEFAULT_CRYPTOSYSTEM = 'ecc'
export const DEFAULT_ECC_CURVE = EccCurve.P_256
export const DEFAULT_RSA_SIZE = RsaSize.B2048

export const DEFAULT_SYMM_ALG = SymmAlg.AES_CTR
export const DEFAULT_SYMM_LEN = SymmKeyLength.B256
export const DEFAULT_CTR_LEN = 64

export const DEFAULT_HASH_ALG = HashAlg.SHA_256

export const DEFAULT_STORE_NAME = 'keystore'
export const DEFAULT_EXCHANGE_KEY_NAME = 'exchange-key'
export const DEFAULT_WRITE_KEY_NAME = 'write-key'

export default {
  ECC_EXCHANGE_ALG,
  ECC_WRITE_ALG,
  RSA_EXCHANGE_ALG,
  RSA_WRITE_ALG,
  SALT_LENGTH,
  DEFAULT_CRYPTOSYSTEM,
  DEFAULT_ECC_CURVE,
  DEFAULT_RSA_SIZE,
  DEFAULT_SYMM_ALG,
  DEFAULT_CTR_LEN,
  DEFAULT_HASH_ALG,
  DEFAULT_STORE_NAME,
  DEFAULT_EXCHANGE_KEY_NAME,
  DEFAULT_WRITE_KEY_NAME,
}

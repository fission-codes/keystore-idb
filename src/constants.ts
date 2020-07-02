import { EccCurve, RsaSize, SymmAlg, SymmKeyLength, HashAlg, CharSize } from './types'

export const ECC_READ_ALG = 'ECDH'
export const ECC_WRITE_ALG = 'ECDSA'
export const RSA_READ_ALG = 'RSA-OAEP'
export const RSA_WRITE_ALG = 'RSASSA-PKCS1-v1_5'
export const SALT_LENGTH = 128

export const DEFAULT_CRYPTOSYSTEM = 'ecc'
export const DEFAULT_ECC_CURVE = EccCurve.P_256
export const DEFAULT_RsaSize = RsaSize.B2048
export const DEFAULT_SYMM_ALG = SymmAlg.AES_CTR
export const DEFAULT_SYMM_LEN = SymmKeyLength.B128
export const DEFAULT_HASH_ALG = HashAlg.SHA_256
export const DEFAULT_CHAR_SIZE = CharSize.B16

export const DEFAULT_STORE_NAME = 'keystore'
export const DEFAULT_READ_KEY_NAME = 'read-key'
export const DEFAULT_WRITE_KEY_NAME = 'write-key'

export default {
  ECC_READ_ALG,
  ECC_WRITE_ALG,
  RSA_READ_ALG,
  RSA_WRITE_ALG,
  SALT_LENGTH,
  DEFAULT_CRYPTOSYSTEM,
  DEFAULT_ECC_CURVE,
  DEFAULT_RsaSize,
  DEFAULT_SYMM_ALG,
  DEFAULT_HASH_ALG,
  DEFAULT_CHAR_SIZE,
  DEFAULT_STORE_NAME,
  DEFAULT_READ_KEY_NAME,
  DEFAULT_WRITE_KEY_NAME,
}

import { ECC_Curve, RSA_Size, SymmAlg, HashAlg } from './types'

export const ECC_READ_ALG = 'ECDH'
export const ECC_WRITE_ALG = 'ECDSA'
export const RSA_READ_ALG = 'RSA-OAEP'
export const RSA_WRITE_ALG = 'RSA-PSS'
export const SALT_LENGTH = 128

export const DEFAULT_CRYPTOSYSTEM = 'ecc'
export const DEFAULT_ECC_CURVE = ECC_Curve.P_256
export const DEFAULT_RSA_SIZE = RSA_Size.B2048
export const DEFAULT_SYMM_ALG = SymmAlg.AES_CTR
export const DEFAULT_HASH_ALG = HashAlg.SHA_256
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
  DEFAULT_RSA_SIZE,
  DEFAULT_SYMM_ALG,
  DEFAULT_HASH_ALG,
  DEFAULT_READ_KEY_NAME,
  DEFAULT_WRITE_KEY_NAME,
}

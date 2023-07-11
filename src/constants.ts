import { EccCurve, SymmAlg, SymmWrappingAlg, SymmKeyLength, HashAlg, CharSize, SaltLength } from './types.js'

// This library is highly opinionated towards ECC. If you want to use RSA, you'll need to change these values, and
// refactor the code to support RSA.
export const ECC_EXCHANGE_ALG = 'ECDH'
export const ECC_WRITE_ALG = 'ECDSA'

export const DEFAULT_ECC_CURVE = EccCurve.P_384
export const DEFAULT_SALT_LENGTH = SaltLength.B128 

export const DEFAULT_SYMM_ALG = SymmAlg.AES_GCM
export const DEFAULT_SYMM_WRAPPING_ALG = SymmWrappingAlg.AES_KW
export const DEFAULT_SYMM_LEN = SymmKeyLength.B256

export const DEFAULT_HASH_ALG = HashAlg.SHA_256
export const DEFAULT_CHAR_SIZE = CharSize.B16

export const DEFAULT_STORE_NAME = 'keystore'
export const DEFAULT_EXCHANGE_KEY_PAIR_NAME = 'exchange-key-pair'
export const DEFAULT_WRITE_KEY_PAIR_NAME = 'write-key-pair'
export const DEFAULT_PASS_KEY_NAME = 'pass-key'

export default {
  ECC_EXCHANGE_ALG,
  ECC_WRITE_ALG,
  DEFAULT_SALT_LENGTH,
  DEFAULT_ECC_CURVE,
  DEFAULT_SYMM_ALG,
  DEFAULT_SYMM_WRAPPING_ALG,
  DEFAULT_HASH_ALG,
  DEFAULT_CHAR_SIZE,
  DEFAULT_STORE_NAME,
  DEFAULT_EXCHANGE_KEY_PAIR_NAME,
  DEFAULT_WRITE_KEY_PAIR_NAME,
  DEFAULT_PASS_KEY_NAME
}

import { structuralClone } from './utils'
import ecc from './ecc'

export const CRYPTOSYSTEM = 'ecc'
export const ECC_CURVE = 'P-256'
export const RSA_SIZE = 2048
export const SYMM_ALG = 'AES-CTR'
export const HASH_ALG = 'SHA-256'
export const READ_KEY_NAME = 'read-key'
export const WRITE_KEY_NAME = 'write-key'

export const defaultConfig = {
  type: CRYPTOSYSTEM,
  curve: ECC_CURVE,
  rsaSize: RSA_SIZE,
  symmAlg: SYMM_ALG,
  hashAlg: HASH_ALG,
  readKeyName: READ_KEY_NAME,
  writeKeyName: WRITE_KEY_NAME,
} as Config

export async function normalize(cfg?: PartialConfig): Promise<Config> {
  if(!cfg){
    return getRecommendation()
  }
  return {
    ...defaultConfig,
    ...cfg,
  }
}

// Attempt a structural clone of an ECC Key (required to store in IndexedDB)
// If it throws an error, use RSA, otherwise use ECC
export async function getRecommendation(): Promise<Config> {
  const keypair = await ecc.makeReadKey(ECC_CURVE)
  try{
    await structuralClone(keypair)
  }catch(err) {
    return {
      ...defaultConfig,
      type: 'rsa'
    }
  }
  return {
    ...defaultConfig,
    type: 'ecc'
  }
}

export default {
  defaultConfig,
  normalize,
  getRecommendation,
}

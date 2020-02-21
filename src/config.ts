import { structuralClone } from './utils'
import ecc from './ecc'
import {
  DEFAULT_CRYPTOSYSTEM,
  DEFAULT_ECC_CURVE,
  DEFAULT_RSA_SIZE,
  DEFAULT_SYMM_ALG,
  DEFAULT_HASH_ALG,
  DEFAULT_READ_KEY_NAME,
  DEFAULT_WRITE_KEY_NAME,
} from './constants'

export const defaultConfig = {
  type: DEFAULT_CRYPTOSYSTEM,
  curve: DEFAULT_ECC_CURVE,
  rsaSize: DEFAULT_RSA_SIZE,
  symmAlg: DEFAULT_SYMM_ALG,
  hashAlg: DEFAULT_HASH_ALG,
  readKeyName: DEFAULT_READ_KEY_NAME,
  writeKeyName: DEFAULT_WRITE_KEY_NAME,
} as Config

export function normalize(cfg?: PartialConfig): Config {
  if(!cfg){
    return defaultConfig
  }
  return {
    ...defaultConfig,
    ...cfg,
  }
}

// Attempt a structural clone of an ECC Key (required to store in IndexedDB)
// If it throws an error, use RSA, otherwise use ECC
export async function eccEnabled(): Promise<boolean> {
  const keypair = await ecc.makeReadKey(DEFAULT_ECC_CURVE)
  try{
    await structuralClone(keypair)
  }catch(err) {
    return false
  }
  return true
}

export default {
  defaultConfig,
  normalize,
  eccEnabled,
}
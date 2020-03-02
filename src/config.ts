import ecc from './ecc/keys'
import {
  DEFAULT_CRYPTOSYSTEM,
  DEFAULT_EccCurve,
  DEFAULT_RsaSize,
  DEFAULT_SYMM_ALG,
  DEFAULT_HASH_ALG,
  DEFAULT_READ_KEY_NAME,
  DEFAULT_WRITE_KEY_NAME
} from './constants'
import { Config, KeyUse, CryptoSystem } from './types'
import utils from './utils'

export const defaultConfig = {
  type: DEFAULT_CRYPTOSYSTEM,
  curve: DEFAULT_EccCurve,
  rsaSize: DEFAULT_RsaSize,
  symmAlg: DEFAULT_SYMM_ALG,
  hashAlg: DEFAULT_HASH_ALG,
  readKeyName: DEFAULT_READ_KEY_NAME,
  writeKeyName: DEFAULT_WRITE_KEY_NAME
} as Config

export function normalize(
  maybeCfg?: Partial<Config>,
  eccEnabled: boolean = true
): Config {
  let cfg
  if (!maybeCfg) {
    cfg = defaultConfig
  } else {
    cfg = {
      ...defaultConfig,
      ...maybeCfg
    }
  }
  if (!maybeCfg?.type) {
    cfg.type = eccEnabled ? CryptoSystem.ECC : CryptoSystem.RSA
  }
  return cfg
}

// Attempt a structural clone of an ECC Key (required to store in IndexedDB)
// If it throws an error, use RSA, otherwise use ECC
export async function eccEnabled(): Promise<boolean> {
  const keypair = await ecc.makeKey(DEFAULT_EccCurve, KeyUse.Read)
  try {
    await utils.structuralClone(keypair)
  } catch (err) {
    return false
  }
  return true
}

export default {
  defaultConfig,
  normalize,
  eccEnabled,
}

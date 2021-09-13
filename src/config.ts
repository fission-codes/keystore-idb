import ecc from './ecc/keys.js'
import {
  DEFAULT_CRYPTOSYSTEM,
  DEFAULT_ECC_CURVE,
  DEFAULT_RSA_SIZE,
  DEFAULT_SYMM_ALG,
  DEFAULT_SYMM_LEN,
  DEFAULT_HASH_ALG,
  DEFAULT_CHAR_SIZE,
  DEFAULT_STORE_NAME,
  DEFAULT_EXCHANGE_KEY_NAME,
  DEFAULT_WRITE_KEY_NAME
} from './constants.js'
import { Config, KeyUse, CryptoSystem, SymmKeyOpts } from './types.js'
import utils from './utils.js'

export const defaultConfig = {
  type: DEFAULT_CRYPTOSYSTEM,
  curve: DEFAULT_ECC_CURVE,
  rsaSize: DEFAULT_RSA_SIZE,
  symmAlg: DEFAULT_SYMM_ALG,
  symmLen: DEFAULT_SYMM_LEN,
  hashAlg: DEFAULT_HASH_ALG,
  charSize: DEFAULT_CHAR_SIZE,
  storeName: DEFAULT_STORE_NAME,
  exchangeKeyName: DEFAULT_EXCHANGE_KEY_NAME,
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
  const keypair = await ecc.makeKeypair(DEFAULT_ECC_CURVE, KeyUse.Exchange)
  try {
    await utils.structuralClone(keypair)
  } catch (err) {
    return false
  }
  return true
}

export function merge(cfg: Config, overwrites: Partial<Config> = {}): Config {
  return {
    ...cfg,
    ...overwrites
  }
}

export function symmKeyOpts(cfg: Config): Partial<SymmKeyOpts> {
  return { alg: cfg.symmAlg, length: cfg.symmLen }
}

export default {
  defaultConfig,
  normalize,
  eccEnabled,
  merge,
  symmKeyOpts
}

import ecc from './ecc/keys.js'
import {
  ECC_EXCHANGE_ALG,
  ECC_WRITE_ALG,
  DEFAULT_ECC_CURVE,
  DEFAULT_SYMM_ALG,
  DEFAULT_SYMM_KEY_LENGTH,
  DEFAULT_HASH_ALG,
  DEFAULT_CHAR_SIZE,
  DEFAULT_STORE_NAME,
  DEFAULT_EXCHANGE_KEY_PAIR_NAME,
  DEFAULT_WRITE_KEY_PAIR_NAME,
  DEFAULT_ESCROW_KEY_NAME,
} from './constants.js'
import { Config, KeyUse, CryptoSystem, SymmKeyOpts } from './types.js'
import utils from './utils.js'

export const defaultConfig = {
  exchangeAlg: ECC_EXCHANGE_ALG,
  writeAlg: ECC_WRITE_ALG,
  curve: DEFAULT_ECC_CURVE,
  symmAlg: DEFAULT_SYMM_ALG,
  symmKeyLength: DEFAULT_SYMM_KEY_LENGTH,
  hashAlg: DEFAULT_HASH_ALG,
  charSize: DEFAULT_CHAR_SIZE,
  storeName: DEFAULT_STORE_NAME,
  exchangeKeyPairName: DEFAULT_EXCHANGE_KEY_PAIR_NAME,
  writeKeyPairName: DEFAULT_WRITE_KEY_PAIR_NAME,
  escrowKeyName: DEFAULT_ESCROW_KEY_NAME
} as Config

export function normalize(
  maybeCfg?: Partial<Config>,
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
  return cfg
}

// Attempt a structural clone of an ECC Key (required to store in IndexedDB)
// If it throws an error, use RSA, otherwise use ECC
export async function eccEnabled(): Promise<boolean> {
  const keypair = await ecc.genKeyPair(DEFAULT_ECC_CURVE, KeyUse.Exchange)

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
  return { alg: cfg.symmAlg, length: cfg.symmKeyLength }
}

export default {
  defaultConfig,
  normalize,
  eccEnabled,
  merge,
  symmKeyOpts,
}

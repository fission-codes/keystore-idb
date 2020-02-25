import ECCKeyStore from './ecc/keystore'
import RSAKeyStore from './rsa/keystore'
import config from './config'
import IDB from './idb'
import { PartialConfig, KeyStore } from './types'

export async function init(maybeCfg?: PartialConfig): Promise<KeyStore>{
  const eccEnabled = await config.eccEnabled()
  if(!eccEnabled && maybeCfg?.type === 'ecc'){
    throw new Error("ECC is not enabled for this browser. Please use RSA instead.")
  }
  
  const cfg = config.normalize(maybeCfg, eccEnabled)

  if(cfg.type === 'ecc'){
    return ECCKeyStore.init(cfg)
  }else if (cfg.type === 'rsa'){
    return RSAKeyStore.init(cfg)
  }else {
    throw new Error("Cryptosystem not supported. Please use ECC or RSA")
  }
}

export async function clear(): Promise<void> {
  return IDB.clear()
}

export default {
  init,
  clear,
}

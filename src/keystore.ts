import ECCKeyStore from './ecc/keystore'
import RSAKeyStore from './rsa/keystore'
import config from './config'
import IDB from './idb'
import { ECCNotEnabled, checkValidCryptoSystem } from './errors'
import { PartialConfig, KeyStore } from './types'

export async function init(maybeCfg?: PartialConfig): Promise<KeyStore>{
  const eccEnabled = await config.eccEnabled()
  if(!eccEnabled && maybeCfg?.type === 'ecc'){
    throw ECCNotEnabled
  }
  
  const cfg = config.normalize(maybeCfg, eccEnabled)

  checkValidCryptoSystem(cfg.type)

  if(cfg.type === 'ecc'){
    return ECCKeyStore.init(cfg)
  }else {
    return RSAKeyStore.init(cfg)
  }
}

export async function clear(): Promise<void> {
  return IDB.clear()
}

export default {
  init,
  clear,
}

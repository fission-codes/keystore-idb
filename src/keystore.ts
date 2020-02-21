import ECCKeyStore from './ecc/keystore'
import RSAKeyStore from './rsa/keystore'
import config from './config'

export async function init(maybeCfg?: PartialConfig): Promise<KeyStore>{
  const eccEnabled = await config.eccEnabled()
  if(!eccEnabled && maybeCfg?.type === 'ecc'){
    throw new Error("ECC is not enabled for this browser. Please use RSA instead.")
  }
  const cfg = {
    ...config.normalize(maybeCfg),
    type: eccEnabled ? 'ecc' : 'rsa'
  } as PartialConfig
  if(cfg.type === 'ecc'){
    return ECCKeyStore.init(cfg)
  }else{
    return RSAKeyStore.init(cfg)
  }
}

export default {
  init
}

import ECCKeyStore from '../ecc/keystore.js';
import config from '../config.js';
import IDB from '../idb.js';
import { Config, KeyStore } from '../types.js';

export async function init(maybeCfg?: Partial<Config>): Promise<KeyStore> {
  const cfg = config.normalize({
    ...(maybeCfg || {}),
  });

  return ECCKeyStore.init(cfg);
}

export async function clear(): Promise<void> {
  return IDB.clear();
}

export default {
  init,
  clear,
};

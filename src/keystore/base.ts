import aes from '../aes'
import idb from '../idb'
import utils from '../utils'
import config from '../config'
import { Config } from '../types'

export default class KeyStoreBase {
  cfg: Config
  readKey: CryptoKeyPair
  writeKey: CryptoKeyPair

  constructor(readKey: CryptoKeyPair, writeKey: CryptoKeyPair, cfg: Config) {
    this.cfg = cfg
    this.readKey = readKey
    this.writeKey = writeKey
  }

  async keyExists(keyName: string): Promise<boolean> {
    return idb.exists(keyName)
  }

  async importSymmKey(keyStr: string, keyName: string, cfg?: Partial<Config>): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await aes.importKey(keyStr, config.symmKeyOpts(mergedCfg))
    await idb.putKey(keyName, key)
  }

  async exportSymmKey(keyName: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await aes.getKey(keyName, config.symmKeyOpts(mergedCfg))
    return aes.exportKey(key)
  }

  async encryptWithSymmKey(msg: string, keyName: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await aes.getKey(keyName, config.symmKeyOpts(mergedCfg))
    const cipherText = await aes.encryptBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      key,
      config.symmKeyOpts(mergedCfg)
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decryptWithSymmKey(cipherText: string, keyName: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await aes.getKey(keyName, config.symmKeyOpts(mergedCfg))
    const msgBytes = await aes.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      key,
      config.symmKeyOpts(mergedCfg)
    )
    return utils.arrBufToStr(msgBytes, mergedCfg.charSize)
  }

}

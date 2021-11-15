import * as uint8arrays from "uint8arrays"

import aes from '../aes/index.js'
import idb from '../idb.js'
import utils from '../utils.js'
import config from '../config.js'
import { Config } from '../types.js'
import { checkIsKeyPair } from '../errors.js'

export default class KeyStoreBase {

  cfg: Config
  protected store: LocalForage

  constructor(cfg: Config, store: LocalForage) {
    this.cfg = cfg
    this.store = store
  }

  async writeKey(): Promise<CryptoKeyPair> {
    const maybeKey = await idb.getKeypair(this.cfg.writeKeyName, this.store)
    return checkIsKeyPair(maybeKey)
  }

  async exchangeKey(): Promise<CryptoKeyPair> {
    const maybeKey = await idb.getKeypair(this.cfg.exchangeKeyName, this.store)
    return checkIsKeyPair(maybeKey)
  }

  async getSymmKey(keyName: string, cfg?: Partial<Config>): Promise<CryptoKey> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const maybeKey = await idb.getKey(keyName, this.store)
    if(maybeKey !== null) {
      return maybeKey
    }
    const key = await aes.makeKey(config.symmKeyOpts(mergedCfg))
    await idb.put(keyName, key, this.store)
    return key
  }

  async keyExists(keyName: string): Promise<boolean> {
    const key = await idb.getKey(keyName, this.store)
    return key !== null
  }

  async deleteKey(keyName: string): Promise<void> {
    return idb.rm(keyName, this.store)
  }

  async destroy(): Promise<void> {
    return idb.dropStore(this.store)
  }

  async importSymmKey(keyStr: string, keyName: string, cfg?: Partial<Config>): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await aes.importKey(keyStr, config.symmKeyOpts(mergedCfg))
    await idb.put(keyName, key, this.store)
  }

  async exportSymmKey(keyName: string, cfg?: Partial<Config>): Promise<string> {
    const key = await this.getSymmKey(keyName, cfg)
    return aes.exportKey(key)
  }

  async encryptWithSymmKey(msg: string, keyName: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await this.getSymmKey(keyName, cfg)
    const cipherText = await aes.encryptBytes(
      uint8arrays.fromString(msg, "utf8"),
      key,
      config.symmKeyOpts(mergedCfg)
    )
    return uint8arrays.toString(new Uint8Array(cipherText), "base64pad")
  }

  async decryptWithSymmKey(cipherText: string, keyName: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const key = await this.getSymmKey(keyName, cfg)
    const msgBytes = await aes.decryptBytes(
      uint8arrays.fromString(cipherText, "base64pad").buffer,
      key,
      config.symmKeyOpts(mergedCfg)
    )
    return uint8arrays.toString(new Uint8Array(msgBytes), "utf8")
  }
}

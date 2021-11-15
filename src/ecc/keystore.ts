import * as uint8arrays from "uint8arrays"

import IDB from '../idb.js'
import keys from './keys.js'
import operations from './operations.js'
import config from '../config.js'
import KeyStoreBase from '../keystore/base.js'
import { KeyStore, Config, KeyUse, CryptoSystem, PrivateKey } from '../types.js'

export class ECCKeyStore extends KeyStoreBase implements KeyStore {

  static async init(maybeCfg?: Partial<Config>): Promise<ECCKeyStore> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
      type: CryptoSystem.ECC
    })
    const { curve, storeName, exchangeKeyName, writeKeyName } = cfg

    const store = IDB.createStore(storeName)
    await IDB.createIfDoesNotExist(exchangeKeyName, () => (
      keys.makeKeypair(curve, KeyUse.Exchange)
    ), store)
    await IDB.createIfDoesNotExist(writeKeyName, () => (
      keys.makeKeypair(curve, KeyUse.Write)
    ), store)

    return new ECCKeyStore(cfg, store)
  }


  async sign(msg: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const writeKey = await this.writeKey()

    return uint8arrays.toString(await operations.sign(
      msg,
      writeKey.privateKey as PrivateKey,
      mergedCfg.hashAlg
    ), "base64pad")
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<boolean> {
    const mergedCfg = config.merge(this.cfg, cfg)

    return operations.verify(
      msg,
      sig,
      publicKey,
      mergedCfg.curve,
      mergedCfg.hashAlg
    )
  }

  async encrypt(
    msg: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const exchangeKey = await this.exchangeKey()

    return uint8arrays.toString(await operations.encrypt(
      msg,
      exchangeKey.privateKey as PrivateKey,
      publicKey,
      mergedCfg.curve
    ), "base64pad")
  }

  async decrypt(
    cipherText: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const exchangeKey = await this.exchangeKey()

    return uint8arrays.toString(
      await operations.decrypt(
        cipherText,
        exchangeKey.privateKey as PrivateKey,
        publicKey,
        mergedCfg.curve
      ),
      "utf8"
    )
  }

  async publicExchangeKey(): Promise<string> {
    const exchangeKey = await this.exchangeKey()
    return operations.getPublicKey(exchangeKey)
  }

  async publicWriteKey(): Promise<string> {
    const writeKey = await this.writeKey()
    return operations.getPublicKey(writeKey)
  }
}

export default ECCKeyStore

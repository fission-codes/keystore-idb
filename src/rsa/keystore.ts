import * as uint8arrays from "uint8arrays"
import IDB from '../idb.js'
import keys from './keys.js'
import operations from './operations.js'
import config from '../config.js'
import utils from '../utils.js'
import KeyStoreBase from '../keystore/base.js'
import { KeyStore, Config, KeyUse, CryptoSystem, Msg, PublicKey, PrivateKey } from '../types.js'

export class RSAKeyStore extends KeyStoreBase implements KeyStore {

  static async init(maybeCfg?: Partial<Config>): Promise<RSAKeyStore> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
      type: CryptoSystem.RSA
    })

    const { rsaSize, hashAlg, storeName, exchangeKeyName, writeKeyName } = cfg
    const store = IDB.createStore(storeName)

    await IDB.createIfDoesNotExist(exchangeKeyName, () => (
      keys.makeKeypair(rsaSize, hashAlg, KeyUse.Exchange)
    ), store)
    await IDB.createIfDoesNotExist(writeKeyName, () => (
      keys.makeKeypair(rsaSize, hashAlg, KeyUse.Write)
    ), store)

    return new RSAKeyStore(cfg, store)
  }


  async sign(msg: Msg, cfg?: Partial<Config>): Promise<string> {
    const writeKey = await this.writeKey()

    return uint8arrays.toString(new Uint8Array(await operations.sign(
      msg,
      writeKey.privateKey as PrivateKey,
    )), "base64pad")
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string | PublicKey,
    cfg?: Partial<Config>
  ): Promise<boolean> {
    const mergedCfg = config.merge(this.cfg, cfg)

    return operations.verify(
      msg,
      sig,
      publicKey,
      mergedCfg.hashAlg
    )
  }

  async encrypt(
    msg: Msg,
    publicKey: string | PublicKey,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)

    return uint8arrays.toString(new Uint8Array(await operations.encrypt(
      msg,
      publicKey,
      mergedCfg.hashAlg
    )), "base64pad")
  }

  async decrypt(
    cipherText: Msg,
  ): Promise<string> {
    const exchangeKey = await this.exchangeKey()

    return uint8arrays.toString(
      new Uint8Array(await operations.decrypt(
        cipherText,
        exchangeKey.privateKey as PrivateKey,
      )),
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

export default RSAKeyStore

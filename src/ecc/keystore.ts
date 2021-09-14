import IDB from '../idb.js'
import keys from './keys.js'
import operations from './operations.js'
import config from '../config.js'
import utils from '../utils.js'
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

    return utils.arrBufToBase64(await operations.sign(
      msg,
      writeKey.privateKey as PrivateKey,
      mergedCfg.charSize,
      mergedCfg.hashAlg
    ))
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
      mergedCfg.charSize,
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

    return utils.arrBufToBase64(await operations.encrypt(
      msg,
      exchangeKey.privateKey as PrivateKey,
      publicKey,
      mergedCfg.charSize,
      mergedCfg.curve
    ))
  }

  async decrypt(
    cipherText: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const exchangeKey = await this.exchangeKey()

    return utils.arrBufToStr(
      await operations.decrypt(
        cipherText,
        exchangeKey.privateKey as PrivateKey,
        publicKey,
        mergedCfg.curve
      ),
      mergedCfg.charSize
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

import IDB from '../idb'
import keys from './keys'
import operations from './operations'
import config from '../config'
import utils from '../utils'
import KeyStoreBase from '../keystore/base'
import { KeyStore, Config, KeyUse, CryptoSystem, Msg, PublicKey } from '../types'

export class RSAKeyStore extends KeyStoreBase implements KeyStore {

  static async init(maybeCfg?: Partial<Config>): Promise<RSAKeyStore> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
      type: CryptoSystem.RSA
    })

    const { rsaSize, hashAlg, storeName, readKeyName, writeKeyName } = cfg
    const store = IDB.createStore(storeName)

    await IDB.createIfDoesNotExist(readKeyName, () => (
      keys.makeKeypair(rsaSize, hashAlg, KeyUse.Exchange)
    ), store)
    await IDB.createIfDoesNotExist(writeKeyName, () => (
      keys.makeKeypair(rsaSize, hashAlg, KeyUse.Write)
    ), store)

    return new RSAKeyStore(cfg, store)
  }


  async sign(msg: Msg, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const writeKey = await this.writeKey()

    return utils.arrBufToBase64(await operations.sign(
      msg,
      writeKey.privateKey,
      mergedCfg.charSize
    ))
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
      mergedCfg.charSize,
      mergedCfg.hashAlg
    )
  }

  async encrypt(
    msg: Msg,
    publicKey: string | PublicKey,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)

    return utils.arrBufToBase64(await operations.encrypt(
      msg,
      publicKey,
      mergedCfg.charSize,
      mergedCfg.hashAlg
    ))
  }

  async decrypt(
    cipherText: Msg,
    publicKey?: string | PublicKey, // unused param so that keystore interfaces match
    cfg?: Partial<Config>
  ): Promise<string> {
    const readKey = await this.readKey()
    const mergedCfg = config.merge(this.cfg, cfg)

    return utils.arrBufToStr(
      await operations.decrypt(
        cipherText,
        readKey.privateKey,
      ),
      mergedCfg.charSize
    )
  }

  async publicReadKey(): Promise<string> {
    const readKey = await this.readKey()
    return operations.getPublicKey(readKey)
  }

  async publicWriteKey(): Promise<string> {
    const writeKey = await this.writeKey()
    return operations.getPublicKey(writeKey)
  }
}

export default RSAKeyStore

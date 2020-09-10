import IDB from '../idb'
import keys from './keys'
import operations from './operations'
import config from '../config'
import utils from '../utils'
import KeyStoreBase from '../keystore/base'
import { KeyStore, Config, KeyUse, CryptoSystem } from '../types'

export class ECCKeyStore extends KeyStoreBase implements KeyStore {

  static async init(maybeCfg?: Partial<Config>): Promise<ECCKeyStore> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
      type: CryptoSystem.ECC
    })
    const { curve, storeName, readKeyName, writeKeyName } = cfg

    const store = IDB.createStore(storeName)
    await IDB.createIfDoesNotExist(readKeyName, () => (
      keys.makeKeypair(curve, KeyUse.Read)
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
      writeKey.privateKey,
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
    const readKey = await this.readKey()

    return utils.arrBufToBase64(await operations.encrypt(
      msg,
      readKey.privateKey,
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
    if(publicKey === undefined) {
      throw new Error("Must pass a public key to decrypt on an ECCKeyStore")
    }
    const mergedCfg = config.merge(this.cfg, cfg)
    const readKey = await this.readKey()

    return utils.arrBufToStr(
      await operations.decrypt(
        cipherText,
        readKey.privateKey,
        publicKey,
        mergedCfg.curve
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

export default ECCKeyStore

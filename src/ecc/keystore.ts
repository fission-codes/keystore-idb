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
    const writeKey = await this.writeKey()

    return await operations.signString(
      msg,
      writeKey.privateKey,
      config.merge(this.cfg, cfg)
    )
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<boolean> {
    return operations.verifyString (
      msg,
      sig,
      publicKey,
      config.merge(this.cfg, cfg)
    )
  }

  async encrypt(
    msg: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const readKey = await this.readKey()

    return operations.encryptString(
      msg,
      readKey.privateKey,
      publicKey,
      config.merge(this.cfg, cfg)
    )
  }

  async decrypt(
    cipherText: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const readKey = await this.readKey()

    return operations.decryptString(
      cipherText,
      readKey.privateKey,
      publicKey,
      config.merge(this.cfg, cfg)
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

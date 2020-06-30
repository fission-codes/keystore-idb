import IDB from '../idb'
import keys from './keys'
import operations from './operations'
import config from '../config'
import KeyStoreBase from '../keystore/base'
import { KeyStore, Config, KeyUse, CryptoSystem } from '../types'

export class RSAKeyStore extends KeyStoreBase implements KeyStore {

  static async init(maybeCfg?: Partial<Config>): Promise<RSAKeyStore> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
      type: CryptoSystem.RSA
    })

    const { rsaSize, hashAlg, storeName, readKeyName, writeKeyName } = cfg
    const store = IDB.createStore(storeName)

    await IDB.createIfDoesNotExist(readKeyName, () => (
      keys.makeKeypair(rsaSize, hashAlg, KeyUse.Read)
    ), store)
    await IDB.createIfDoesNotExist(writeKeyName, () => (
      keys.makeKeypair(rsaSize, hashAlg, KeyUse.Write)
    ), store)

    return new RSAKeyStore(cfg, store)
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
    return await operations.verifyString(
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
    return await operations.encryptString(
      msg,
      publicKey,
      config.merge(this.cfg, cfg)
    )
  }

  async decrypt(
    cipherText: string,
    publicKey?: string, // unused param so that keystore interfaces match
    cfg?: Partial<Config>
  ): Promise<string> {
    const readKey = await this.readKey()

    return await operations.decryptString(
      cipherText,
      readKey.privateKey,
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

export default RSAKeyStore

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

    const sigBytes = await operations.signBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      writeKey.privateKey,
      mergedCfg.hashAlg
    )
    return utils.arrBufToBase64(sigBytes)
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<boolean> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const pubkey = await keys.importPublicKey(publicKey, mergedCfg.curve, KeyUse.Write)

    return operations.verifyBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      utils.base64ToArrBuf(sig),
      pubkey,
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
    const pubkey = await keys.importPublicKey(publicKey, mergedCfg.curve, KeyUse.Read)

    const cipherText = await operations.encryptBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      readKey.privateKey,
      pubkey,
      config.symmKeyOpts(mergedCfg)
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decrypt(
    cipherText: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const readKey = await this.readKey()
    const pubkey = await keys.importPublicKey(publicKey, mergedCfg.curve, KeyUse.Read)

    const msgBytes = await operations.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      readKey.privateKey,
      pubkey,
      config.symmKeyOpts(mergedCfg)
    )
    return utils.arrBufToStr(msgBytes, mergedCfg.charSize)
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

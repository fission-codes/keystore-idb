import keys from './keys'
import operations from './operations'
import config from '../config'
import utils from '../utils'
import KeyStoreBase from '../keystore/base'
import { KeyStore, Config, KeyUse, CryptoSystem } from '../types'

export class ECCKeyStore extends KeyStoreBase implements KeyStore {

  async sign(msg: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const sigBytes = await operations.signBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      this.writeKey.privateKey,
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
    const pubkey = await keys.importPublicKey(publicKey, mergedCfg.curve, KeyUse.Read)
    const cipherText = await operations.encryptBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      this.readKey.privateKey,
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
    const pubkey = await keys.importPublicKey(publicKey, mergedCfg.curve, KeyUse.Read)
    const msgBytes = await operations.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      this.readKey.privateKey,
      pubkey,
      config.symmKeyOpts(mergedCfg)
    )
    return utils.arrBufToStr(msgBytes, mergedCfg.charSize)
  }

  async publicReadKey(): Promise<string> {
    return operations.getPublicKey(this.readKey)
  }

  async publicWriteKey(): Promise<string> {
    return operations.getPublicKey(this.writeKey)
  }
}

export async function init(maybeCfg?: Partial<Config>): Promise<ECCKeyStore> {
  const cfg = config.normalize({
    ...(maybeCfg || {}),
    type: CryptoSystem.ECC
  })
  const { curve, readKeyName, writeKeyName } = cfg
  const readKey = await keys.getKey(curve, readKeyName, KeyUse.Read)
  const writeKey = await keys.getKey(curve, writeKeyName, KeyUse.Write)
  return new ECCKeyStore(readKey, writeKey, cfg)
}

export default {
  ECCKeyStore,
  init
}

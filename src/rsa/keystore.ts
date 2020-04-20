import keys from './keys'
import operations from './operations'
import config from '../config'
import utils from '../utils'
import KeyStoreBase from '../keystore/base'
import { KeyStore, Config, KeyUse, CryptoSystem } from '../types'

export class RSAKeyStore extends KeyStoreBase implements KeyStore {

  async sign(msg: string, cfg?: Partial<Config>): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const sigBytes = await operations.signBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      this.writeKey.privateKey
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
    const pubkey = await keys.importPublicKey(publicKey, mergedCfg.hashAlg, KeyUse.Write)
    return operations.verifyBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      utils.base64ToArrBuf(sig),
      pubkey
    )
  }

  async encrypt(
    msg: string,
    publicKey: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const pubkey = await keys.importPublicKey(publicKey, mergedCfg.hashAlg, KeyUse.Read)
    const cipherText = await operations.encryptBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      pubkey
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decrypt(
    cipherText: string,
    publicKey?: string, //unused param so that keystore interfaces match
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg)
    const msgBytes = await operations.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      this.readKey.privateKey
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

export async function init(maybeCfg?: Partial<Config>): Promise<RSAKeyStore> {
  const cfg = config.normalize({
    ...(maybeCfg || {}),
    type: CryptoSystem.RSA
  })
  const { rsaSize, hashAlg, readKeyName, writeKeyName } = cfg
  const readKey = await keys.getKey(rsaSize, hashAlg, readKeyName, KeyUse.Read)
  const writeKey = await keys.getKey(
    rsaSize,
    hashAlg,
    writeKeyName,
    KeyUse.Write
  )
  return new RSAKeyStore(readKey, writeKey, cfg)
}

export default {
  RSAKeyStore,
  init,
}

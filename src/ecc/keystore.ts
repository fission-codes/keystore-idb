import keys from './keys'
import operations from './operations'
import config from '../config'
import utils from '../utils'
import KeyStoreBase from '../keystore/base'
import { KeyStore, Config, KeyUse, CharSize, CryptoSystem } from '../types'

export class ECCKeyStore extends KeyStoreBase implements KeyStore {

  async sign(msg: string): Promise<string> {
    const sigBytes = await operations.signBytes(
      utils.strToArrBuf(msg, this.cfg.charSize),
      this.writeKey.privateKey,
      this.cfg.hashAlg
    )
    return utils.arrBufToBase64(sigBytes)
  }

  async verify(
    msg: string,
    sig: string,
    publicKey: string
  ): Promise<boolean> {
    const pubkey = await keys.importPublicKey(publicKey, this.cfg.curve, KeyUse.Write)
    return operations.verifyBytes(
      utils.strToArrBuf(msg, this.cfg.charSize),
      utils.base64ToArrBuf(sig),
      pubkey,
      this.cfg.hashAlg
    )
  }

  async encrypt(
    msg: string,
    publicKey: string
  ): Promise<string> {
    const pubkey = await keys.importPublicKey(publicKey, this.cfg.curve, KeyUse.Read)
    const opts  = { alg: this.cfg.symmAlg, length: this.cfg.symmLen }
    const cipherText = await operations.encryptBytes(
      utils.strToArrBuf(msg, this.cfg.charSize),
      this.readKey.privateKey,
      pubkey,
      opts
    )
    return utils.arrBufToBase64(cipherText)
  }

  async decrypt(
    cipherText: string,
    publicKey: string
  ): Promise<string> {
    const pubkey = await keys.importPublicKey(publicKey, this.cfg.curve, KeyUse.Read)
    const opts  = { alg: this.cfg.symmAlg, length: this.cfg.symmLen }
    const msgBytes = await operations.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      this.readKey.privateKey,
      pubkey,
      opts
    )
    return utils.arrBufToStr(msgBytes, this.cfg.charSize)
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

import aes from '../aes/index.js';
import pbkdf2 from '../pbkdf2/index.js';
import idb from '../idb.js';
import utils from '../utils.js';
import config from '../config.js';
import { CipherText, Config } from '../types.js';
import { KeyDoesNotExist, checkIsKeyPair } from '../errors.js';
import { DEFAULT_SALT_LENGTH, DEFAULT_SYMM_ALG } from '../constants.js';

export default class KeyStoreBase {
  cfg: Config;
  protected store: LocalForage;

  constructor(cfg: Config, store: LocalForage) {
    this.cfg = cfg;
    this.store = store;
  }

  static async initBase(maybeCfg?: Partial<Config>): Promise<KeyStoreBase> {
    const cfg = config.normalize({
      ...(maybeCfg || {}),
    });
    const { storeName } = cfg;
    const store = idb.createStore(storeName);
    return new KeyStoreBase(cfg, store);
  }

  /* KeyStore Management */

  async keyExists(keyName: string): Promise<boolean> {
    const key = await idb.getKey(keyName, this.store);
    return key !== null;
  }
  async keyPairExists(keyPairName: string): Promise<boolean> {
    const keyPair = await idb.getKeypair(keyPairName, this.store);
    return keyPair !== null;
  }
  async deleteKey(keyName: string): Promise<void> {
    return idb.rm(keyName, this.store);
  }
  async destroy(): Promise<void> {
    return idb.dropStore(this.store);
  }

  /* Base Asymmetric Key Management */

  async getExchangeKeyPair(): Promise<CryptoKeyPair> {
    const maybeKey = await idb.getKeypair(
      this.cfg.exchangeKeyPairName,
      this.store
    );
    return checkIsKeyPair(maybeKey);
  }

  async getWriteKeyPair(): Promise<CryptoKeyPair> {
    const maybeKey = await idb.getKeypair(
      this.cfg.writeKeyPairName,
      this.store
    );
    return checkIsKeyPair(maybeKey);
  }

  /* Escrow Key Management */

  async deriveEscrowKey(
    passphrase: string,
    saltStr?: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const salt = saltStr
      ? utils.base64ToArrBuf(saltStr)
      : utils.randomBuf(DEFAULT_SALT_LENGTH);
    const key = await pbkdf2.deriveKey(
      passphrase,
      salt,
      mergedCfg.hashAlg,
      ['wrapKey', 'unwrapKey'],
      config.symmKeyOpts(mergedCfg)
    );
    await idb.put(this.cfg.escrowKeyName, key, this.store);
    return saltStr ?? utils.arrBufToBase64(salt);
  }

  /* Symmetric Key Management */

  // Key Generation and Import
  async genSymmKey(
    keyName: string,
    uses: KeyUsage[] = ['encrypt', 'decrypt'],
    cfg?: Partial<Config>
  ): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    await idb.createIfDoesNotExist(
      keyName,
      () => aes.genKey(uses, config.symmKeyOpts(mergedCfg)),
      this.store
    );
  }
  async importSymmKey(
    keyStr: string,
    keyName: string,
    uses: KeyUsage[] = ['encrypt', 'decrypt'],
    cfg?: Partial<Config>
  ): Promise<void> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const key = await aes.importKey(
      keyStr,
      uses,
      config.symmKeyOpts(mergedCfg)
    );
    await idb.put(keyName, key, this.store);
  }

  // Getters and Exporters
  async getSymmKey(keyName: string): Promise<CryptoKey> {
    const maybeKey = await idb.getKey(keyName, this.store);
    if (maybeKey === null) {
      throw KeyDoesNotExist;
    }
    return maybeKey;
  }

  async exportSymmKey(keyName: string): Promise<string> {
    const key = await this.getSymmKey(keyName);
    return aes.exportKey(key);
  }

  // Key Operations
  async encryptWithSymmKey(
    msg: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const key = await this.getSymmKey(keyName);
    const cipherText = await aes.encryptBytes(
      utils.strToArrBuf(msg, mergedCfg.charSize),
      key,
      config.symmKeyOpts(mergedCfg)
    );
    return utils.arrBufToBase64(cipherText);
  }

  async decryptWithSymmKey(
    cipherText: string,
    keyName: string,
    cfg?: Partial<Config>
  ): Promise<string> {
    const mergedCfg = config.merge(this.cfg, cfg);
    const key = await this.getSymmKey(keyName);
    const msgBytes = await aes.decryptBytes(
      utils.base64ToArrBuf(cipherText),
      key,
      config.symmKeyOpts(mergedCfg)
    );
    return utils.arrBufToStr(msgBytes, mergedCfg.charSize);
  }

  async wrapKeyWithSymmKey(
    keyToWrap: CryptoKey,
    keyName: string
  ): Promise<CipherText> {
    const key = await this.getSymmKey(keyName);
    return await aes.wrapKey(keyToWrap, key);
  }

  async unwrapKeyWithSymmKey(
    wrappedKey: CipherText,
    keyName: string,
    keyParams: AlgorithmIdentifier = { name: DEFAULT_SYMM_ALG },
    extractable = true,
    uses: KeyUsage[] = ['encrypt', 'decrypt']
  ): Promise<CryptoKey> {
    const key = await this.getSymmKey(keyName);
    return await aes.unwrapKey(wrappedKey, key, keyParams, extractable, uses);
  }
}

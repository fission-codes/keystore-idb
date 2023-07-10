import { webcrypto } from 'one-webcrypto';
import utils from '../utils.js';
import { DEFAULT_SYMM_ALG } from '../constants.js';
import {
  SymmKey,
  SymmKeyOpts,
  SymmWrappingKey,
  SymmWrappingKeyOpts,
  SymmWrappingAlg,
  SymmAlg,
  CipherText,
  Msg,
  ExportKeyFormat,
} from '../types.js';
import {
  InvalidIvLength,
  InvalidCipherTextLength,
  UnsupportedSymmWrappingCrypto,
  UnsupportedSymmCrypto,
} from '../errors.js';

export async function encryptBytes(
  msg: Msg,
  key: SymmKey,
  opts?: Partial<SymmKeyOpts>
): Promise<CipherText> {
  const data = utils.normalizeUtf16ToBuf(msg);
  const alg = opts?.alg || DEFAULT_SYMM_ALG;

  // Note: we only support AES-GCM here
  // If you want support for more symmetric key algorithms, add implementations here
  if (alg !== SymmAlg.AES_GCM) {
    throw UnsupportedSymmCrypto;
  }

  const iv = opts?.iv || utils.randomBuf(16);
  const cipherBuf = await webcrypto.subtle.encrypt(
    {
      name: alg,
      iv,
    },
    key,
    data
  );
  return utils.joinCipherText(iv, cipherBuf);
}

export async function decryptBytes(
  msg: Msg,
  key: SymmKey,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const cipherText = utils.normalizeBase64ToBuf(msg);
  const alg = opts?.alg || DEFAULT_SYMM_ALG;

  // Note: we only support AES-GCM here
  // If you want support for more symmetric key algorithms, add implementations here

  if (alg !== SymmAlg.AES_GCM) {
    throw UnsupportedSymmCrypto;
  }

  const [iv, cipherBytes] = utils.splitCipherText(cipherText);
  // Check lengths
  if (iv.byteLength !== 16) {
    throw InvalidIvLength;
  } else if (
    cipherBytes.byteLength === 0 ||
    cipherBytes.byteLength % 16 !== 0
  ) {
    throw InvalidCipherTextLength;
  }

  const msgBuff = await webcrypto.subtle.decrypt(
    {
      name: alg,
      iv,
    },
    key,
    cipherBytes
  );
  return msgBuff;
}

export async function encrypt(
  msg: Msg,
  key: SymmKey,
  opts?: Partial<SymmKeyOpts>
): Promise<string> {
  const cipherText = await encryptBytes(msg, key, opts);
  return utils.arrBufToBase64(cipherText);
}

export async function decrypt(
  msg: Msg,
  key: SymmKey,
  opts?: Partial<SymmKeyOpts>
): Promise<string> {
  const msgBytes = await decryptBytes(msg, key, opts);
  return utils.arrBufToStr(msgBytes, 16);
}

export async function wrapKey(
  format: ExportKeyFormat,
  key: CryptoKey,
  wrappingKey: SymmWrappingKey,
  opts?: Partial<SymmWrappingKeyOpts>
): Promise<string> {
  const alg = opts?.alg || SymmWrappingAlg.AES_KW;

  // Note: we only support AES-KW here
  // If you want support for more symmetric key wrapping algorithms, add implementations here
  if (alg !== SymmWrappingAlg.AES_KW) {
    throw UnsupportedSymmWrappingCrypto;
  }

  const cipherText = await webcrypto.subtle.wrapKey(format, key, wrappingKey, {
    name: alg,
  });
  return utils.arrBufToBase64(cipherText);
}

export async function unwrapKey(
  format: ExportKeyFormat,
  wrappedKey: string,
  unwrappingKey: SymmWrappingKey,
  unwrappedKeyAlgParams: AlgorithmIdentifier,
  extractable: boolean,
  keyUsages: KeyUsage[],
  opts?: Partial<SymmWrappingKeyOpts>
): Promise<CryptoKey> {
  const alg = opts?.alg || SymmWrappingAlg.AES_KW;

  // Note: we only support AES-KW here
  // If you want support for more symmetric key wrapping algorithms, add implementations here
  if (alg !== SymmWrappingAlg.AES_KW) {
    throw UnsupportedSymmWrappingCrypto;
  }

  const cipherText = utils.normalizeBase64ToBuf(wrappedKey);
  const key = await webcrypto.subtle.unwrapKey(
    format,
    cipherText,
    unwrappingKey,
    { name: alg },
    unwrappedKeyAlgParams,
    extractable,
    keyUsages
  );
  return key;
}

export default {
  encryptBytes,
  decryptBytes,
  encrypt,
  decrypt,
  wrapKey,
  unwrapKey,
};

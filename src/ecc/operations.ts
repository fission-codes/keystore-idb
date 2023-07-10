import aes from '../aes/index.js';
import { normalizeBase64ToBuf, normalizeUnicodeToBuf } from '../utils.js';
import {
  DEFAULT_CHAR_SIZE,
  DEFAULT_HASH_ALG,
  ECC_EXCHANGE_ALG,
  ECC_WRITE_ALG,
  DEFAULT_SYMM_ALG,
  DEFAULT_SYMM_LEN,
  DEFAULT_SYMM_WRAPPING_ALG,
} from '../constants.js';
import {
  CharSize,
  Msg,
  PrivateKey,
  PublicKey,
  HashAlg,
  SymmKey,
  SymmKeyOpts,
  SymmWrappingKey,
  SymmWrappingKeyOpts,
  ExportKeyFormat,
} from '../types.js';
import { webcrypto } from 'one-webcrypto';

export async function sign(
  msg: Msg,
  privateKey: PrivateKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<ArrayBuffer> {
  return webcrypto.subtle.sign(
    { name: ECC_WRITE_ALG, hash: { name: hashAlg } },
    privateKey,
    normalizeUnicodeToBuf(msg, charSize)
  );
}

export async function verify(
  msg: Msg,
  sig: Msg,
  publicKey: PublicKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  hashAlg: HashAlg = DEFAULT_HASH_ALG
): Promise<boolean> {
  return webcrypto.subtle.verify(
    { name: ECC_WRITE_ALG, hash: { name: hashAlg } },
    publicKey,
    normalizeBase64ToBuf(sig),
    normalizeUnicodeToBuf(msg, charSize)
  );
}

export async function encrypt(
  msg: Msg,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  charSize: CharSize = DEFAULT_CHAR_SIZE,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const cipherKey = await getSharedSymmKey(privateKey, publicKey, opts);
  return aes.encryptBytes(
    normalizeUnicodeToBuf(msg, charSize),
    cipherKey,
    opts
  );
}

export async function decrypt(
  msg: Msg,
  privateKey: PrivateKey,
  publicKey: PublicKey,
  opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
  const cipherKey = await getSharedSymmKey(privateKey, publicKey, opts);
  return aes.decryptBytes(normalizeBase64ToBuf(msg), cipherKey, opts);
}

export async function wrapKey(
  format: ExportKeyFormat,
  key: CryptoKey,
  wrappingKey: PrivateKey,
  publicKey: PublicKey,
  opts?: Partial<SymmWrappingKeyOpts>
): Promise<string> {
  const wrappingCipherKey = await getSharedSymmWrappingKey(
    wrappingKey,
    publicKey,
    opts
  );
  return aes.wrapKey(format, key, wrappingCipherKey, opts);
}

export async function unwrapKey(
  format: ExportKeyFormat,
  wrappedKey: string,
  unwrappingKey: PrivateKey,
  publicKey: PublicKey,
  params: AlgorithmIdentifier,
  uses: KeyUsage[],
  opts?: Partial<SymmWrappingKeyOpts>
): Promise<CryptoKey> {
  const wrappingCipherKey = await getSharedSymmWrappingKey(
    unwrappingKey,
    publicKey,
    opts
  );
  return aes.unwrapKey(
    format,
    wrappedKey,
    wrappingCipherKey,
    params,
    true,
    uses,
    opts
  );
}

/* Key Derivation Helpers */

async function getSharedSymmKey(
  privateKey: PrivateKey,
  publicKey: PublicKey,
  opts?: Partial<SymmKeyOpts>
): Promise<SymmKey> {
  return webcrypto.subtle.deriveKey(
    { name: ECC_EXCHANGE_ALG, public: publicKey },
    privateKey,
    {
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

async function getSharedSymmWrappingKey(
  privateKey: PrivateKey,
  publicKey: PublicKey,
  opts?: Partial<SymmWrappingKeyOpts>
): Promise<SymmWrappingKey> {
  return webcrypto.subtle.deriveKey(
    { name: ECC_EXCHANGE_ALG, public: publicKey },
    privateKey,
    {
      name: opts?.alg || DEFAULT_SYMM_WRAPPING_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export default {
  sign,
  verify,
  encrypt,
  decrypt,
  wrapKey,
  unwrapKey,
};

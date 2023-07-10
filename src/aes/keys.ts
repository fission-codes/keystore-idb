import { webcrypto } from 'one-webcrypto';
import utils from '../utils.js';
import {
  DEFAULT_SYMM_ALG,
  DEFAULT_SYMM_LEN,
  DEFAULT_SYMM_WRAPPING_ALG,
} from '../constants.js';
import {
  SymmKey,
  SymmKeyOpts,
  SymmWrappingKey,
  SymmWrappingKeyOpts,
  ExportKeyFormat,
  HashAlg,
} from '../types.js';

export async function genKey(opts?: Partial<SymmKeyOpts>): Promise<SymmKey> {
  return webcrypto.subtle.generateKey(
    {
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function importKey(
  base64key: string,
  opts?: Partial<SymmKeyOpts>
): Promise<SymmKey> {
  const buf = utils.base64ToArrBuf(base64key);
  return webcrypto.subtle.importKey(
    ExportKeyFormat.RAW,
    buf,
    {
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function deriveKey(
  seed: string,
  salt: ArrayBuffer,
  hashAlg: HashAlg,
  opts?: Partial<SymmKeyOpts>
): Promise<SymmKey> {
  const enc = new TextEncoder();
  const baseKey = await webcrypto.subtle.importKey(
    ExportKeyFormat.RAW,
    enc.encode(seed),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  const alg: Pbkdf2Params = {
    name: 'PBKDF2',
    salt: salt,
    iterations: 100000,
    hash: hashAlg,
  };
  return webcrypto.subtle.deriveKey(
    alg,
    baseKey,
    {
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function genWrappingKey(
  opts?: Partial<SymmWrappingKeyOpts>
): Promise<SymmWrappingKey> {
  return webcrypto.subtle.generateKey(
    {
      name: opts?.alg || DEFAULT_SYMM_WRAPPING_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    true,
    ['wrapKey', 'unwrapKey']
  );
}

export async function importWrappingKey(
  base64key: string,
  opts?: Partial<SymmWrappingKeyOpts>
): Promise<SymmWrappingKey> {
  const buf = utils.base64ToArrBuf(base64key);
  return webcrypto.subtle.importKey(
    ExportKeyFormat.RAW,
    buf,
    {
      name: opts?.alg || DEFAULT_SYMM_WRAPPING_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export async function deriveWrappingKey(
  seedPhrase: string,
  salt: ArrayBuffer,
  hashAlg: HashAlg,
  opts?: Partial<SymmWrappingKeyOpts>
): Promise<SymmWrappingKey> {
  const enc = new TextEncoder();
  const baseKey = await webcrypto.subtle.importKey(
    ExportKeyFormat.RAW,
    enc.encode(seedPhrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  const alg: Pbkdf2Params = {
    name: 'PBKDF2',
    salt: salt,
    iterations: 100000,
    hash: hashAlg,
  };
  return webcrypto.subtle.deriveKey(
    alg,
    baseKey,
    {
      name: opts?.alg || DEFAULT_SYMM_WRAPPING_ALG,
      length: opts?.length || DEFAULT_SYMM_LEN,
    },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export default {
  genKey,
  genWrappingKey,
  importKey,
  importWrappingKey,
  deriveKey,
  deriveWrappingKey,
};

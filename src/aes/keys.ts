import { webcrypto } from 'one-webcrypto';
import utils from '../utils.js';
import { DEFAULT_SYMM_ALG, DEFAULT_SYMM_KEY_LENGTH } from '../constants.js';
import { SymmKey, SymmKeyOpts, ExportKeyFormat } from '../types.js';

/**
 * Generate a new symmetric key
 * @param uses The uses of the key, [ 'encrypt', 'decrypt' ] by default
 * @param opts The options for the key
 * @returns The generated symmetric key
 */
export async function genKey(
  uses: KeyUsage[] = ['encrypt', 'decrypt'],
  opts?: Partial<SymmKeyOpts>
): Promise<SymmKey> {
  return webcrypto.subtle.generateKey(
    {
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_KEY_LENGTH,
    },
    true,
    uses
  );
}

/**
 * Import a symmetric key from a base64 string
 * @param base64key The base64 encoded symmetric key
 * @param uses The uses of the key, [ 'encrypt', 'decrypt' ] by default
 * @param opts The options for the key
 * @returns The imported symmetric key
 */
export async function importKey(
  base64key: string,
  uses: KeyUsage[] = ['encrypt', 'decrypt'],
  opts?: Partial<SymmKeyOpts>
): Promise<SymmKey> {
  const buf = utils.base64ToArrBuf(base64key);
  return webcrypto.subtle.importKey(
    ExportKeyFormat.RAW,
    buf,
    {
      name: opts?.alg || DEFAULT_SYMM_ALG,
      length: opts?.length || DEFAULT_SYMM_KEY_LENGTH,
    },
    false,
    uses
  );
}

/**
 * Export a symmetric key to a base64 string
 * @param key The symmetric key to export
 * @returns The base64 encoded symmetric key
 */
export async function exportKey(key: CryptoKey): Promise<string> {
  const exp = await webcrypto.subtle.exportKey(ExportKeyFormat.RAW, key);
  return utils.arrBufToBase64(exp);
}

export default {
  genKey,
  importKey,
  exportKey,
};

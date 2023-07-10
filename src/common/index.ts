import { ExportKeyFormat } from '../types';
import utils from '../utils';
import { webcrypto } from 'one-webcrypto';

export async function exportKey(
  key: CryptoKey,
  format: ExportKeyFormat
): Promise<string> {
  const exp = await webcrypto.subtle.exportKey(format, key);
  return utils.arrBufToBase64(exp);
}

export async function exportKeyBytes(
  key: CryptoKey,
  format: ExportKeyFormat
): Promise<ArrayBuffer> {
  return await webcrypto.subtle.exportKey(format, key);
}

import localforage from 'localforage'
import { checkIsKeyPair, checkIsKey } from './errors.js'

/* istanbul ignore next */
export function createStore(name: string): LocalForage {
  return localforage.createInstance({ name })
}

export async function createIfDoesNotExist(id: string, makeFn: () => Promise<CryptoKeyPair | CryptoKey>, store: LocalForage = localforage): Promise<void> {
  if(await exists(id, store)) {
    return
  }
  const key = await makeFn()
  await put(id, key, store)
}

/* istanbul ignore next */
export async function put(id: string, key: CryptoKeyPair | CryptoKey, store: LocalForage = localforage): Promise<CryptoKeyPair | CryptoKey> {
	return store.setItem(id, key)
}

/* istanbul ignore next */
export async function getKeypair(id: string, store: LocalForage = localforage): Promise<CryptoKeyPair | null> {
  return get(id, checkIsKeyPair, store)
}

/* istanbul ignore next */
export async function getKey(id: string, store: LocalForage = localforage): Promise<CryptoKey | null> {
  return get(id, checkIsKey, store)
}

/* istanbul ignore next */
export async function get<T>(id: string, checkFn: (obj: unknown) => T | null, store: LocalForage = localforage) {
  const item = await store.getItem(id)
  return item === null ? null : checkFn(item)
}

/* istanbul ignore next */
export async function exists(id: string, store: LocalForage = localforage): Promise<boolean> {
  const key = await store.getItem(id)
  return key !== null
}

/* istanbul ignore next */
export async function rm(id: string, store: LocalForage = localforage): Promise<void> {
  return store.removeItem(id)
}

export async function dropStore(store: LocalForage): Promise<void> {
  return store.dropInstance()
}

/* istanbul ignore next */
export async function clear(store?: LocalForage): Promise<void> {
  if(store){
    return dropStore(store)
  }else {
    return localforage.clear()
  }
}

export default {
  createStore,
  createIfDoesNotExist,
  put,
  getKeypair,
	getKey,
  exists,
  rm,
  dropStore,
	clear
}

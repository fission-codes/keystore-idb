import localForage from 'localforage'

/* istanbul ignore next */
export async function putKey(id: string, key: CryptoKeyPair | CryptoKey) {
	return localForage.setItem(id, key)
}

/* istanbul ignore next */
export async function getKey(id: string): Promise<CryptoKeyPair | CryptoKey | null> {
	return localForage.getItem(id) || null
}

/* istanbul ignore next */
export async function exists(id: string): Promise<boolean> {
  const key = await getKey(id)
  return key !== null
}

/* istanbul ignore next */
export async function clear(): Promise<void> {
	await localForage.clear()
}

export default {
	putKey,
	getKey,
	exists,
	clear
}

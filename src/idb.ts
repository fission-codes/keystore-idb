import localForage from 'localforage'

/* istanbul ignore next */
export async function putKey(id: string, keypair: CryptoKeyPair) {
	return localForage.setItem(id, keypair)
}

/* istanbul ignore next */
export async function getKey(id: string): Promise<CryptoKeyPair | undefined> {
	return localForage.getItem(id)
}

/* istanbul ignore next */
export async function clear(): Promise<void> {
	await localForage.clear()
}

export default {
	putKey,
	getKey,
	clear
}

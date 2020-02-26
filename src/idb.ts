import localForage from 'localforage'

export async function putKey(id: string, keypair: CryptoKeyPair) {
	return localForage.setItem(id, keypair)
}

export async function getKey(id: string): Promise<CryptoKeyPair | undefined> {
	return localForage.getItem(id)
}

export async function clear(): Promise<void> {
	await localForage.clear()
}

export default {
	putKey,
	getKey,
	clear
}

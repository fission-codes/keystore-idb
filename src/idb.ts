type ModifyStoreFN = (store: IDBObjectStore) => void

export async function putKey(id: string, keypair: CryptoKeyPair) {
  return new Promise((resolve, reject) => {
		callOnStore((store) => {
			try{
				const putData = store.put({ id, keypair })
				putData.onsuccess = resolve
				putData.onerror = reject
			}catch(err) {
				console.error(err)
			}
		})
	})
}

export async function getKey(id: string): Promise<CryptoKeyPair | undefined> {
  return new Promise((resolve, reject) => {
    callOnStore((store) => {
      const getData = store.get(id)
      getData.onsuccess = async function () {
        if(getData.result && getData.result.keypair){
          return resolve(getData.result.keypair)
        }else {
					return resolve(undefined)
        }
      }
      getData.onerror = reject
    })
  })
}

// from https://gist.github.com/saulshanabrook/b74984677bccd08b028b30d9968623f5
export async function callOnStore(fn_: ModifyStoreFN) {
	const windowIDB = window as any
	// This works on all devices/browsers, and uses IndexedDBShim as a final fallback 
	var indexedDB = windowIDB.indexedDB || windowIDB.mozIndexedDB || windowIDB.webkitIndexedDB || windowIDB.msIndexedDB || windowIDB.shimIndexedDB;

	// Open (or create) the database
	var open = indexedDB.open("MyDatabase", 1);

	// Create the schema
	open.onupgradeneeded = function() {
	    var db = open.result;
	    var store = db.createObjectStore("MyObjectStore", {keyPath: "id"});
	};

	open.onsuccess = function() {
	    // Start a new transaction
	    var db = open.result;
	    var tx = db.transaction("MyObjectStore", "readwrite");
	    var store = tx.objectStore("MyObjectStore");

	    fn_(store)

	    // Close the db when the transaction is done
	    tx.oncomplete = function() {
	        db.close();
	    };
	}
}

export default {
	putKey,
	getKey,
}

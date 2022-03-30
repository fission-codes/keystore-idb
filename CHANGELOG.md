# Changelog

### v0.15.5

- Support a `max` parameter (based on rejection sampling) in `randomBuf` rng.

### v0.15.4

- Bump one-webcrypto to 1.0.3 for wider bundler support.

### v0.15.3

- Internally use the one-webcrypto library for referring to the webcrypto API

### v0.15.2

- Add `AES-GCM` to the list of valid symmetric algorithms (`SymmAlg`)
- Internally dynamically refer to either the NodeJS or Browser webcrypto API

### v0.15.1

Importing `keystore-idb/lib/*` directly should now work as intended. This allows bundlers to use the "real" import paths (eg. `import "keystore-idb/lib/utils.js"`) in addition to the "proxy" import paths (eg. `import "keystore-idb/utils.js"`). One reason to do this could be that you want your library to support both new and old bundlers, ie. bundlers with or without `exports` support in their `package.json` file.


### v0.15.0

- Renamed read key to exchange key.
- Switched out `Buffer` usage with `uint8arrays` library.
- Built with esbuild instead of rollup.



### v0.14.0

Use the `globalThis` global object instead of `window`.

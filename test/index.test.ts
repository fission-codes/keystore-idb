import KeyStore from '../src/keystore'
import config from '../src/config'

jest.mock('../src/idb')

describe('keystore', () => {
  describe('init', () => {
    describe('ecc enabled', () => {

      beforeEach(async () => {
        const mock = jest.spyOn(config, 'eccEnabled')
        mock.mockResolvedValue(true)
      })

      it('should instantiate a keystore and cleat it without error', async () => {
        const resp = await KeyStore.init()
        expect(resp).toBeInstanceOf(KeyStore)
        await resp.clear()
      })
    })
  })
})

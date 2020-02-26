import { ECCKeyStore } from '../../src/ecc/keystore'
import { RSAKeyStore } from '../../src/rsa/keystore'
import config from '../../src/config'
import { KeyStore } from '../../src/types'
import { mock } from './mock'

const sinon = require('sinon')

type KeystoreMethodOpts = {
  desc: string
  type: 'ecc' | 'rsa'
  mockModule: object
  mockMethod: string
  mockResp: any
  reqFn: (ks: KeyStore) => Promise<any>
  expectedResp: any
  expectedParams: any
}

export const keystoreMethod = (opts: KeystoreMethodOpts) => {
  describe(opts.desc, () => {
    let fake: sinon.SinonSpy
    let response: any

    beforeAll(async () => {
      sinon.restore()
      fake = sinon.fake.returns(new Promise(r => r(opts.mockResp)))
      sinon.stub(opts.mockModule, opts.mockMethod).callsFake(fake)
      const ks = opts.type === 'ecc' ?
        new ECCKeyStore(mock.keys, mock.writeKeys, config.defaultConfig) :
        new RSAKeyStore(mock.keys, mock.writeKeys, config.defaultConfig)
      response = await opts.reqFn(ks)
    })

    it('should call the library function once', () => {
      expect(fake.callCount).toEqual(1)
    })

    it('should call the library function with the expected params', () => {
      expect(fake.args[0]).toEqual(opts.expectedParams)
    })

    it('should return the expectedResp', () => {
      expect(response).toEqual(opts.expectedResp)
    })
  })
}


import { ECCKeyStore } from '../../src/ecc/keystore'
import { RSAKeyStore } from '../../src/rsa/keystore'
import config from '../../src/config'
import { KeyStore } from '../../src/types'
import { mock } from './mock'

const sinon = require('sinon')

type Mock = {
  mod: object
  meth: string
  resp: any
  params: any
}

type KeystoreMethodOpts = {
  desc: string
  type: 'ecc' | 'rsa'
  mocks: Mock[]
  reqFn: (ks: KeyStore) => Promise<any>
  expectedResp: any
  // expectedParams: any
}

export const keystoreMethod = (opts: KeystoreMethodOpts) => {
  describe(opts.desc, () => {
    let fakes = [] as sinon.SinonSpy[]
    let response: any

    beforeAll(async () => {
      sinon.restore()
      opts.mocks.forEach(mock => {
        const fake = sinon.fake.returns(new Promise(r => r(mock.resp)))
        sinon.stub(mock.mod, mock.meth).callsFake(fake)
        fakes.push(fake)
      })
      // fake = sinon.fake.returns(new Promise(r => r(opts.mockResp)))
      // sinon.stub(opts.mockModule, opts.mockMethod).callsFake(fake)
      const ks = opts.type === 'ecc' ?
        new ECCKeyStore(mock.keys, mock.writeKeys, config.defaultConfig) :
        new RSAKeyStore(mock.keys, mock.writeKeys, config.defaultConfig)
      response = await opts.reqFn(ks)
    })

    opts.mocks.forEach((mock, i) => {
      it(`should call ${mock.meth} once`, () => {
        expect(fakes[i].callCount).toEqual(1)
      })

      it(`should call the library function with the expected params`, () => {
        expect(fakes[i].args[0]).toEqual(mock.params)
      })
    })

    it('should return the expectedResp', () => {
      expect(response).toEqual(opts.expectedResp)
    })
  })
}


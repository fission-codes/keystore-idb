import KeyStore from '../src'
import ecc from '../src/ecc'
import rsa from '../src/rsa'
import config from '../src/config'
import errors from '../src/errors'
import { CryptoSystem } from '../src/types'
import IDB from '../src/idb'

import { mock } from './utils'

const sinon = require('sinon')

describe('keystore', () => {
  describe('init', () => {
    describe('ecc enabled', () => {
      let fakeEnabled: sinon.SinonSpy
      let fakeGet: sinon.SinonSpy

      beforeEach(async () => {
        sinon.restore()
        fakeEnabled = sinon.fake.returns(new Promise(r => r(true)))
        sinon.stub(config, 'eccEnabled').callsFake(fakeEnabled)

        fakeGet = sinon.fake.returns(new Promise(r => r(mock.keys)))
        sinon.stub(IDB, 'getKey').callsFake(fakeGet)
      })

      it('should instantiate an ecc keystore if not specificed', async () => {
        const resp = await KeyStore.init()
        const eccKeystore = await ecc.init()
        expect(resp).toStrictEqual(eccKeystore)
      })

      it('should instantiate an rsa keystore if specificed', async () => {
        const resp = await KeyStore.init({ type: CryptoSystem.RSA })
        const rsaKeystore = await rsa.init()
        expect(resp).toStrictEqual(rsaKeystore)
      })
    })

    describe('ecc not enabled', () => {
      let fakeEnabled: sinon.SinonSpy
      let fakeGet: sinon.SinonSpy

      beforeEach(async () => {
        sinon.restore()
        fakeEnabled = sinon.fake.returns(new Promise(r => r(false)))
        sinon.stub(config, 'eccEnabled').callsFake(fakeEnabled)

        fakeGet = sinon.fake.returns(new Promise(r => r(mock.keys)))
        sinon.stub(IDB, 'getKey').callsFake(fakeGet)
      })

      it('should instantiate an rsa keystore if not specificed', async () => {
        const resp = await KeyStore.init()
        const rsaKeystore = await rsa.init()
        expect(resp).toStrictEqual(rsaKeystore)
      })

      it('should throw an error if ecc is specified', async () => {
        let error
        try{
          await KeyStore.init({ type: CryptoSystem.ECC })
        }catch(err){
          error = err
        }
        expect(error).toEqual(errors.ECCNotEnabled)
      })

      it('should throw an error if an unsupported type of crypto is specified', async () => {
        let error
        try{
          await KeyStore.init({ type: 'some-other-crypto' as any })
        }catch(err){
          error = err
        }
        expect(error).toEqual(errors.UnsupportedCrypto)
      })

    })
  })

  describe('clear', () => {
    let fake = sinon.SinonSpy

    beforeAll(async () => {
      fake = sinon.fake.returns(new Promise(r => r()))
      sinon.stub(IDB, 'clear').callsFake(fake)
      await KeyStore.clear()
    })

    it('calls IDB.clear once', () => {
      expect(fake.callCount).toEqual(1)
    })
  })
})

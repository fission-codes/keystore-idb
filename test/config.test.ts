import config from '../src/config'
import utils from '../src/utils'
import { mock } from './crypto-utils'

const sinon = require('sinon')

describe('config', () => {
  describe('eccEnabled', () => {

    beforeEach(() => sinon.restore())

    describe('structural clone works', () => {
      let fakeClone: sinon.SinonSpy
      let fakeMake: sinon.SinonSpy
      let response: boolean

      beforeAll(async () => {
        fakeClone = sinon.fake.returns(new Promise(r => r()))
        sinon.stub(utils, 'structuralClone').callsFake(fakeClone)

        fakeMake = sinon.fake.returns(new Promise(r => r(mock.keys)))
        window.crypto.subtle.generateKey = fakeMake

        response = await config.eccEnabled()
      })

      it('calls structural clone once', () => {
        expect(fakeClone.callCount).toEqual(1)
      })

      it('returns true', () => {
        expect(response).toEqual(true)
      })
    })

    describe('structural clone does not works', () => {
      let fakeClone: sinon.SinonSpy
      let fakeMake: sinon.SinonSpy
      let response: boolean

      beforeAll(async () => {
        fakeClone = sinon.fake.returns(
          new Promise((resp, rej) => rej(new Error("cannot structural clone")))
        )
        sinon.stub(utils, 'structuralClone').callsFake(fakeClone)

        fakeMake = sinon.fake.returns(new Promise(r => r(mock.keys)))
        window.crypto.subtle.generateKey = fakeMake

        response = await config.eccEnabled()
      })

      it('calls structural clone once', () => {
        expect(fakeClone.callCount).toEqual(1)
      })

      it('returns false', () => {
        expect(response).toEqual(false)
      })
    })
  })


  describe('normalize', () => {
    it('defaults to defaultConfig', () => {
      const cfg = config.normalize()
      expect(cfg).toEqual(config.defaultConfig)
    })

    it('merges with default config', () => {
      const cfg = config.normalize({
        readKeyName: 'test'
      })
      const modifiedDef = {
        ...config.defaultConfig,
        readKeyName: 'test'
      }
      expect(cfg).toEqual(modifiedDef)
    })

    it('sets ecc if enabled', () => {
      const cfg = config.normalize({}, true)
      const modifiedDef = {
        ...config.defaultConfig,
        type: 'ecc'
      }
      expect(cfg).toEqual(modifiedDef)
    })

    it('sets rsa if ecc not enabled', () => {
      const cfg = config.normalize({}, false)
      const modifiedDef = {
        ...config.defaultConfig,
        type: 'rsa'
      }
      expect(cfg).toEqual(modifiedDef)
    })


    it('does not overwrite type if user defined', () => {
      const cfg = config.normalize({type: 'rsa'}, true)
      const modifiedDef = {
        ...config.defaultConfig,
        type: 'rsa'
      }
      expect(cfg).toEqual(modifiedDef)
    })
  })
})

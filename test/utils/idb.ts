import IDB from '../../src/idb'
import sinon from './sinon'

/* eslint-disable @typescript-eslint/no-explicit-any */
type IdbReqOpts = {
  desc: string;
  req: () => Promise<any>;
  expectedResponse: any;
  fakePutResp?: sinon.SinonSpy;
  fakeGetResp?: sinon.SinonSpy;
  fakeMakeResp?: sinon.SinonSpy;
  putParams?: any;
  getParams?: any;
  makeParams?: any;
  putCount: number;
  getCount: number;
  makeCount: number;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

const pluralTimes = (times: number): string => {
  return `${times} ${times === 1 ? 'time' : 'times'}`
}

export const idbMethod = (opts: IdbReqOpts): void => {
  return describe(opts.desc, () => {
    let fakeMake: sinon.SinonSpy
    let fakePut: sinon.SinonSpy
    let fakeGet: sinon.SinonSpy
    let response: any // eslint-disable-line @typescript-eslint/no-explicit-any 

    beforeEach(async () => {
      fakePut = sinon.fake.returns(new Promise(r => r(opts.fakePutResp)))
      sinon.stub(IDB, 'putKey').callsFake(fakePut)

      fakeGet = sinon.fake.returns(new Promise(r => r(opts.fakeGetResp)))
      sinon.stub(IDB, 'getKey').callsFake(fakeGet)

      fakeMake = sinon.fake.returns(new Promise(r => r(opts.fakeMakeResp)))
      window.crypto.subtle.generateKey = fakeMake
      response = await opts.req()
    })

    it(`calls IDB.getKey ${pluralTimes(opts.getCount)}`, () => {
      expect(fakeGet.callCount).toEqual(opts.getCount)
    })

    it(`calls IDB.putKey ${pluralTimes(opts.putCount)}`, () => {
      expect(fakePut.callCount).toEqual(opts.putCount)
    })

    it(`calls makeKey ${pluralTimes(opts.makeCount)}`, () => {
      expect(fakeMake.callCount).toEqual(opts.makeCount)
    })

    it('passes the correct params to IDB.getKey', () => {
      expect(fakeGet.args[0]).toEqual(opts.getParams)
    })

    it('passes the correct params to IDB.putKey', () => {
      expect(fakePut.args[0]).toEqual(opts.putParams)
    })

    it('passes the correct params to makeKey', () => {
      expect(fakeMake.args[0]).toEqual(opts.makeParams)
    })

    it('returns expected response', () => {
      expect(response).toEqual(opts.expectedResponse)
    })
  })
}


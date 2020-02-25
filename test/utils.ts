const sinon = require('sinon')

type Req = () => Promise<any>

type ParamCheck = {
  desc: string
  req: Req
  params: object
}

type ShouldThrow = {
  desc: string
  req: Req
  error: Error
}

type WebCryptoReqOpts = {
  desc: string
  setMock: (fake: sinon.SinonSpy) => void
  simpleReq: Req
  mockResp: any
  expectedResp?: any
  paramChecks: ParamCheck[]
  shouldThrows: ShouldThrow[]
}

export const cryptoMethod = (opts: WebCryptoReqOpts) => {
  return describe(opts.desc, () => {
    let fake: sinon.SinonSpy

    beforeEach(async () => {
      fake = sinon.fake.returns(new Promise(r => r(opts.mockResp)))
      opts.setMock(fake)
    })

    it('sends only one request', async () => {
      await opts.simpleReq()
      expect(fake.callCount).toEqual(1)
    })

    it('returns expected response', async () => {
      const response = await opts.simpleReq()
      if(opts.expectedResp){
        expect(response).toEqual(opts.expectedResp)
      }else{
        expect(response).toEqual(opts.mockResp)
      }
    })

    opts.paramChecks.forEach(test => {
      it(test.desc, async () => {
        await test.req()
        expect(fake.args[0]).toEqual(test.params)
      })
    })

    opts.shouldThrows.forEach(test => {
      it(test.desc, async() => {
        let error
        try {
          await test.req()
        }catch(err){
          error = err
        }
        expect(error).toBe(test.error)
      })
    })

  })
}

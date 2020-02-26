import utils from '../src/utils'

const sinon = require('sinon')

type Req = () => Promise<any>
type ParamCheckFn = (params: any) => boolean

type ParamCheck = {
  desc: string
  req: Req
  params: object | ParamCheckFn
}

type ShouldThrow = {
  desc: string
  req: Req
  error: Error
}

type WebCryptoReqOpts = {
  desc: string
  setMock: (fake: sinon.SinonSpy) => void
  mockResp: any
  expectedResp?: any
  simpleReq: Req
  simpleParams: object
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

    it('correctly passes params', async () => {
      await opts.simpleReq()
      expect(fake.args[0]).toEqual(opts.simpleParams)
    })

    opts.paramChecks.forEach(test => {
      it(test.desc, async () => {
        await test.req()
        if(typeof test.params === 'function'){
          expect(test.params(fake.args[0])).toBeTruthy()

        }else {
          expect(fake.args[0]).toEqual(test.params)
        }
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

export const mock = {
  keys: {
    publicKey: { type: 'pub' } as any,
    privateKey: { type: 'priv' } as any
  } as any,
  symmKey: { type: 'symm' } as any,
  publicKeyHex: 'abcdef1234567890',
  publicKeyBase64: 'q83vEjRWeJA=',
  msgBytes: utils.strToArrBuf("test msg bytes", 8),
  signature: utils.strToArrBuf("test signature", 8),
  cipherText: utils.strToArrBuf("test encrypted bytes", 8),
}

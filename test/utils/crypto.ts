/* eslint-disable @typescript-eslint/no-explicit-any */
type Req = () => Promise<any>
type ParamCheckFn = (params: any) => boolean

type ParamCheck = {
  desc: string;
  req: Req;
  params: object | ParamCheckFn;
}

type ShouldThrow = {
  desc: string;
  req: Req;
  error: Error;
}

type WebCryptoReqOpts = {
  desc: string;
  setMock: (fake: jest.Mock) => void;
  mockResp: any;
  expectedResp?: any;
  simpleReq: Req;
  simpleParams?: object;
  paramChecks: ParamCheck[];
  shouldThrows: ShouldThrow[];
}
/* eslint-enable @typescript-eslint/no-explicit-any */

export const cryptoMethod = (opts: WebCryptoReqOpts): void => {
  return describe(opts.desc, () => {
    let fake: jest.Mock
   
    beforeEach(async () => {
      fake = jest.fn(() => new Promise(r => r(opts.mockResp)))
      opts.setMock(fake)
    })

    it('sends only one request', async () => {
      await opts.simpleReq()
      expect(fake).toBeCalledTimes(1)
    })

    it('returns expected response', async () => {
      const response = await opts.simpleReq()
      if(opts.expectedResp){
        expect(response).toEqual(opts.expectedResp)
      }else{
        expect(response).toEqual(opts.mockResp)
      }
    })

    if(opts.simpleParams !== undefined){
      it('correctly passes params', async () => {
        await opts.simpleReq()
        expect(fake.mock.calls[0]).toEqual(opts.simpleParams)
      })
    }

    opts.paramChecks.forEach(test => {
      it(test.desc, async () => {
        await test.req()
        if(typeof test.params === 'function'){
          expect(test.params(fake.mock.calls[0])).toBeTruthy()

        }else {
          expect(fake.mock.calls[0]).toEqual(test.params)
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

export function arrBufEq(fstBuf: ArrayBuffer, sndBuf: ArrayBuffer): boolean {
  const fst = new Uint8Array(fstBuf)
  const snd = new Uint8Array(sndBuf)
  if (fst.length !== snd.length) {
    return false
  }
  for(let i=0; i<fst.length; i++) {
    if(fst[i] !== snd[i]) {
      return false
    }
  }
  return true
}

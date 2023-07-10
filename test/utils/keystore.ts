import KeyStore from '../../src/keystore';
import config from '../../src/config';
import idb from '../../src/idb';
import { KeyStoreInterface } from '../../src/types';
import { mock } from './mock';

/* eslint-disable @typescript-eslint/no-explicit-any */
type Mock = {
  mod: any;
  meth: string;
  resp: any;
  params: any;
};

type KeystoreMethodOpts = {
  desc: string;
  mocks: Mock[];
  reqFn: (ks: KeyStoreInterface) => Promise<any>;
  expectedResp?: any;
};
/* eslint-enable @typescript-eslint/no-explicit-any */

export const keystoreMethod = (opts: KeystoreMethodOpts): void => {
  describe(opts.desc, () => {
    const fakes = [] as jest.SpyInstance[];
    let response: any; // eslint-disable-line @typescript-eslint/no-explicit-any

    beforeAll(async () => {
      jest.resetAllMocks();
      jest.spyOn(idb, 'getKeypair').mockImplementation((keyName) => {
        return keyName === 'exchange-key-pair' ? mock.keys : mock.writeKeys;
      });

      opts.mocks.forEach((mock) => {
        const fake = jest.spyOn(mock.mod, mock.meth);
        fake.mockResolvedValue(mock.resp);
        fakes.push(fake);
      });

      const ks = new KeyStore(config.defaultConfig, mock.idbStore);
      response = await opts.reqFn(ks);
    });

    opts.mocks.forEach((mock, i) => {
      it(`should call ${mock.meth} once`, () => {
        expect(fakes[i]).toBeCalledTimes(1);
      });

      it(`should call the library function with the expected params`, () => {
        expect(fakes[i].mock.calls[0]).toEqual(mock.params);
      });
    });

    if (opts.expectedResp !== undefined) {
      it('should return the expectedResp', () => {
        expect(response).toEqual(opts.expectedResp);
      });
    }
  });
};

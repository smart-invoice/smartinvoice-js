import expect from 'expect.js';
import SmartInvoice from '../src/index';

const host = 'http://localhost:10010';
const nockBack = require('nock').back;

nockBack.fixtures = `${__dirname}/fixtures/`;
nockBack.setMode('record');

describe('Constructor', () => {
  it('Should throw error when host is not set', () => {
    const sm = new SmartInvoice();
    expect(() => {
      sm.login();
    }).to.throwException(/Host is not set check your config/);
  });
});

describe('Identity', () => {
  it('Should generate new identity', () => {
    expect(SmartInvoice.createIdentity()).to.have.keys(
      'did',
      'verifyKey',
      'encryptionPublicKey',
      'secret',
    );
  });
  it('Should return new JWT token', (done) => {
    const userDID = 'did:sov:1701248245165';
    const invitationCode = 'unittest';
    const sm = new SmartInvoice({
      host,
    });

    nockBack('login.json')
      .then(({
        nockDone,
      }) => {
        sm.login(userDID, invitationCode).then((res) => {
          expect(res.data).to.have.key('token');
        }).catch(() => {}).then(() => {
          nockDone();
          done();
        });
      });
  });
});

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
  beforeEach(() => {
    sm = new SmartInvoice({
      host,
    });
  });

  it('Should register new identity', () => {
    const invitationCode = 'unittest';
    const identity = SmartInvoice.createIdentity();
    return nockBack('register.json').then(({
      nockDone,
    }) => sm.register(identity.encryptionPublicKey, identity.did, invitationCode).then((res) => {
      expect(res.status).to.be(200);
    }).then(() => {
      nockDone();
    }));
  });


  it('Should generate new identity', () => {
    expect(SmartInvoice.createIdentity()).to.have.keys(
      'did',
      'verifyKey',
      'encryptionPublicKey',
      'secret',
    );
  });
  it('Should return error code when user is not registered', () => {
    const userDID = 'did:sov:37118448445165';
    const invitationCode = 'unittest';

    return nockBack('login-fail.json')
      .then(({
        nockDone,
      }) => sm.login(userDID, invitationCode).catch((error) => {
        expect(error.response.status).to.be(401);
        expect(error.response.data.message).to.be('User not registered');
      }).then(() => {
        nockDone();
      }));
  });
  it('Should return new JWT token', () => {
    const userDID = 'did:sov:1701248245165';
    const invitationCode = 'unittest';

    return nockBack('login.json')
      .then(({
        nockDone,
      }) => {
        return sm.login(userDID, invitationCode).then((res) => {
          expect(res.data).to.have.key('token');
        }).catch(() => {}).then(() => {
          nockDone();
        });
      });
  });
});

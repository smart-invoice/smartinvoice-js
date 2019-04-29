import expect from 'expect.js';
import nock from 'nock';
import SmartInvoice from '../src/index';

const host = 'http://localhost:10010';
const nockBack = nock.back;

const identity = {
  did: 'CdQ9A19S6oppr4CYda3M8i',
  verifyKey: '7La5hvpwdaRCNgsoz64aFdaYzGT9gs5pWamGufUqkrT9',
  encryptionPublicKey: '2vZLop4WEkZAXFHyhvRac1PmnZV7oB6Wz6JmPAVegz6P',
  secret: {
    seed: '32bbc71999d494cf7786d9affa67f5d8b4d0cc116ab00acfceef840f842d2563',
    signKey: '4R3TUZSP1vvxFGE5kKtGALBJgrXFZjWPi3LV5AixmLst',
    encryptionPrivateKey: '4R3TUZSP1vvxFGE5kKtGALBJgrXFZjWPi3LV5AixmLst',
  },
};

let sm = '';

nockBack.fixtures = `${__dirname}/fixtures/`;
nockBack.setMode('record');

describe('Constructor', () => {
  it('Should throw error when host is not set', () => {
    sm = new SmartInvoice({}, SmartInvoice.createIdentity());
    expect(() => {
      sm.login();
    }).to.throwException(/Host is not set check your config/);
  });
});

describe('Identity', () => {
  const invitationCode = 'unittest';

  beforeEach(() => {
    sm = new SmartInvoice(
      {
        host,
        invitationCode,
      },
      identity,
    );
  });

  it('Should register new identity', () => nockBack('register.json').then(({ nockDone }) => sm
    .register()
    .then((res) => {
      expect(res.status).to.be(200);
    })
    .catch((error) => {
      nockDone(error);
    })
    .then(() => {
      nockDone();
    })));

  it('Should generate new identity', () => {
    expect(SmartInvoice.createIdentity()).to.have.keys(
      'did',
      'verifyKey',
      'encryptionPublicKey',
      'secret',
    );
  });

  it('Should return error code when user is not registered', () => nockBack('login-fail.json').then(({ nockDone }) => sm
    .login()
    .catch((error) => {
      expect(error.response.status).to.be(401);
      expect(error.response.data.message).to.be('User not registered');
    })
    .then(() => {
      nockDone();
    })));

  it('Should return new JWT token', () => nockBack('login.json').then(({ nockDone }) => sm
    .login()
    .then((res) => {
      expect(res.data).to.have.key('toksen');
    })
    .catch((error) => {
      nockDone(error);
    })
    .then(() => {
      nockDone();
    })));

  describe('Authenticated user', () => {
    beforeEach(() => {
      sm = new SmartInvoice(
        {
          host,
          invitationCode,
        },
        identity,
      );
    });

    it('Should fetch identity from did directory', () => {
      const did = `did:sov:${sm.identity.did}`;
      return nockBack('login.json').then(({ nockDone }) => sm.login().then(res => nockBack('fetch-identity.json').then(({ nockDone }) => sm.fetchIdentityFor(did).then((res) => {
        expect(res.data).to.have.keys('additionalInformation', 'publicKey');
        expect(res.data.publicKey).to.be(sm.identity.encryptionPublicKey);
        expect(res.data).to.not.be(undefined);
        nockDone();
      }))));
    });

    describe('Sending document', () => {});

    describe('Encryption', () => {
      beforeEach(() => {
        sm = new SmartInvoice(
          {
            host,
            invitationCode,
          },
          identity,
        );
      });

      it('Should encrypt document with AES key', () => {
        const file = 'Dummy content representing file';
        const encryptedFile = sm.encryptWithAES(file);
        expect(file).to.be(sm.decryptWithAES(encryptedFile));
      });

      it('Should encrypt payload for recevier and send it to the network', () => {
        const payload = { website: 'https;//payasyouwant.example/user/123' };
        const receiverDID = 'did:sov:CdQ9A19S6oppr4CYda3M8i';
        const dri = 'QmWATWQ7fVPP2EFGu71UkfnqhYXDYH566qy47CnJDgvs8u';
        return nockBack('login.json').then(({ nockDone }) => {
          sm.login().then(res => nockBack('fetch-identity2.json').then(({ nockDone }) => sm
            .encryptTransactionPayloadFor(receiverDID, payload)
            .then((encryptedTransactionPayload) => {
              expect(encryptedTransactionPayload).to.have.keys(
                'encryptedReceiverMessage',
                'encryptedSenderMessage',
              );
              return nockBack('fetch-identity.json').then(({ nockDone }) => sm
                .decryptTransactionPayload(
                  `did:sov:${sm.identity.did}`,
                  encryptedTransactionPayload.encryptedSenderMessage,
                )
                .then((decryptedPayload) => {
                  expect(JSON.parse(decryptedPayload)).to.have.keys('aes', 'payload');

                  return nockBack('send-document.json').then(({ nockDone }) => sm
                    .sendDocument(dri, encryptedTransactionPayload, receiverDID)
                    .then((response) => {
                      expect(response).to.have.keys('transactionId');
                      nockDone();
                    })
                    .catch((error) => {
                      nockDone(error);
                    }));
                }));
            })));
        });
      });
    });
  });
});

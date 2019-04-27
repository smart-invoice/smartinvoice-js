import expect from 'expect.js';
import nock from 'nock';
import SmartInvoice from '../src/index';

const host = 'http://localhost:10010';
const nockBack = nock.back;

let sm = '';

nockBack.fixtures = `${__dirname}/fixtures/`;
nockBack.setMode('record');

describe('Constructor', () => {
  it('Should throw error when host is not set', () => {
    sm = new SmartInvoice();
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
    return nockBack('register.json').then(({ nockDone }) => sm
      .register(identity.encryptionPublicKey, identity.did, invitationCode)
      .then((res) => {
        expect(res.status).to.be(200);
      })
      .then(() => {
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

    return nockBack('login-fail.json').then(({ nockDone }) => sm
      .login(userDID, invitationCode)
      .catch((error) => {
        expect(error.response.status).to.be(401);
        expect(error.response.data.message).to.be('User not registered');
      })
      .then(() => {
        nockDone();
      }));
  });

  it('Should return new JWT token', () => {
    const userDID = 'did:sov:VkVZLvjVCNEdp6w7UKBjtq';
    const invitationCode = 'unittest';

    return nockBack('login.json').then(({ nockDone }) => sm
      .login(userDID, invitationCode)
      .then((res) => {
        expect(res.data).to.have.key('tok5en');
      })
      .catch(() => {})
      .then(() => {
        nockDone();
      }));
  });

  describe('Authenticated user', () => {
    beforeEach(() => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTU2MDc1NzQsInVzZXJESUQiOiJkaWQ6c292OlZrVlpMdmpWQ05FZHA2dzdVS0JqdHEiLCJvcmdESUQiOiJhY21lIiwib3JnRW5kcG9pbnQiOiJodHRwOi8vbG9jYWxob3N0OjEwMDEwIiwiaW52aXRhdGlvbkNvZGUiOiJ1bml0dGVzdCIsImlhdCI6MTU1NTU3MTU3NH0.lFFpWlM900hqQQxL1QO7bdmW19YOepHc26XOnKzdypA';
      const identity = {
        did: 'LqVJn9uWFSLF7fw5h9vjA4',
        verifyKey: 'Bp4CKMxjw1UdBXQ4Giy1vnndbDQgVUk9eTbJzzbFxe3w',
        encryptionPublicKey: 'CyekceffS36LguAa6d5PJTFDmQW4C9gSYTSEasefda72',
        secret: {
          seed: 'f70d8e5c25d932c6dd3c0e71a0a21cdec6908653a5779fc4670b088e958922b0',
          signKey: 'HdPh3bBbTCwRe332KMfPxZhbmq7K31UUVvxLEKEaeBi7',
          encryptionPrivateKey: 'HdPh3bBbTCwRe332KMfPxZhbmq7K31UUVvxLEKEaeBi7',
        },
      };
      sm = new SmartInvoice(
        {
          host,
          jwt,
        },
        identity,
      );
    });

    it('Should fetch identity from did directory', () => {
      const did = 'did:sov:LqVJn9uWFSLF7fw5h9vjA4';
      return nockBack('fetch-identity.json').then(({ nockDone }) => sm.fetchIdentityFor(did).then((res) => {
        expect(res.data).to.have.keys('additionalInformation', 'publicKey');
        expect(res.data.publicKey).to.be(sm.identity.encryptionPublicKey);
        expect(res.data).to.not.be(undefined);
        nockDone();
      }));
    });

    describe('Sending document', () => {});
  });
});

describe('Encryption', () => {
  beforeEach(() => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTU2MDc1NzQsInVzZXJESUQiOiJkaWQ6c292OlZrVlpMdmpWQ05FZHA2dzdVS0JqdHEiLCJvcmdESUQiOiJhY21lIiwib3JnRW5kcG9pbnQiOiJodHRwOi8vbG9jYWxob3N0OjEwMDEwIiwiaW52aXRhdGlvbkNvZGUiOiJ1bml0dGVzdCIsImlhdCI6MTU1NTU3MTU3NH0.lFFpWlM900hqQQxL1QO7bdmW19YOepHc26XOnKzdypA';

    const identity = {
      did: 'LqVJn9uWFSLF7fw5h9vjA4',
      verifyKey: 'Bp4CKMxjw1UdBXQ4Giy1vnndbDQgVUk9eTbJzzbFxe3w',
      encryptionPublicKey: 'CyekceffS36LguAa6d5PJTFDmQW4C9gSYTSEasefda72',
      secret: {
        seed: 'f70d8e5c25d932c6dd3c0e71a0a21cdec6908653a5779fc4670b088e958922b0',
        signKey: 'HdPh3bBbTCwRe332KMfPxZhbmq7K31UUVvxLEKEaeBi7',
        encryptionPrivateKey: 'HdPh3bBbTCwRe332KMfPxZhbmq7K31UUVvxLEKEaeBi7',
      },
    };
    sm = new SmartInvoice(
      {
        host,
        jwt,
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
    const receiverDID = 'did:sov:VkVZLvjVCNEdp6w7UKBjtq';
    const dri = 'QmWATWQ7fVPP2EFGu71UkfnqhYXDYH566qy47CnJDgvs8u';

    return nockBack('fetch-identity2.json').then(({ nockDone }) => sm.encryptTransactionPayloadFor(receiverDID, payload).then((encryptedTransactionPayload) => {
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
    }));
  });
});

import sovrinDID from 'sovrin-did';
import axios from 'axios';
import CryptoJS from 'crypto-js';
import crypto from 'crypto';
import Base64js from 'base64-js';

/**
 * <p>Get the configuration object.</p>
 *
 * <p>
 * The configuration object is a shared singleton object within the application,
 * attained by calling require('smartinvoice-sdk').
 * </p>
 *
 * <p>
 * Usually you'll specify a CONFIG variable at the top of your .js file
 * for file/module scope. If you want the root of the object, you can do this:
 * </p>
 * <pre>
 * var SmartInvoice = require('smartinvoice-sdk');
 * </pre>
 *
 *
 * @method constructor
 * @param {String} apiHost The url for the Smart Invoice Api
 * @return SmartInvoice {object} - The top level SmartInvoice object
 */

export default class SmartInvoice {
  constructor(instanceConfig, userIdentity) {
    this.config = instanceConfig;
    this.aesSecret = '';
    this.aesIv = '';
    this.identity = userIdentity;
    // TODO use autogenrated nonce and decouple authentication from encryption
    // TODO notice string must be exactly 24 bytes
    // Due to the sovrin lib we are using encryption with authentication where
    // we have to pass nonce
    // we would get rid of it as soon as we would find better lib for dealing with ecds keys
    this.nonce = Base64js.toByteArray('difacturdifacturdifacturdifactur');
  }

  /**
   * Set host for SmartInvoice API
   * @parma {String} uri URI of the API ednpoint
   */
  set host(uri) {
    this.config.host = uri;
  }

  /**
   * Get host uri for SmartInvoice API endpoint
   * @return {String} Host endpoint URI string
   */
  get host() {
    if (this.config === undefined || this.config.host === undefined) {
      throw Error('Host is not set check your config');
    }
    return this.config.host;
  }

  set jwt(jwt) {
    this.config.jwt = jwt;
  }

  get jwt() {
    if (this.config === undefined || this.config.jwt === undefined) {
      throw Error('JWT not set, check yout configuration');
    }
    return this.config.jwt;
  }

  /**
   * Generate new DID base identity
   * It include public and private key. Currently supported only Sovrin but in the feature
   * this would be extended to other DID Methods.
   * @return {Object} object including public and private key for the identity.
   */
  static createIdentity() {
    return sovrinDID.gen();
  }

  fetchIdentityFor(did) {
    let url = this.host;
    url += `/api/did/${did}`;
    return axios.get(url, {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.jwt}`,
      },
    });
  }

  /**
   * Login user and get JWT token for next calls
   * @param  {String} did User DID (Decentralize Identifier), currently only did:sov is supported
   * @param  {String} invitationCode The second number
   * @return {Promise} axios promise and if success Json Web Token (JWT)
   */
  login(userDID, invitationCode) {
    // TODO use identity keys for JWT
    let url = this.host;
    url += '/api/login?';
    return axios.get(url, {
      params: {
        invitationCode,
        userDID,
      },
    });
  }

  /**
   *  Register new user within DID directory
   *
   * @param {String} userPublicKey User public key
   * @param {String} userDID User DID (Decentralize Identifier), currently only did:sov is supported
   * @param {String} invitationCode - Invitation code for joining Pilot network
   * @return {Promise} axios promise and if success http code 200
   */
  register(userPublicKey, userDID, invitationCode) {
    let url = this.host;
    url += '/api/register';
    return axios.post(url, {
      invitationCode,
      userDID,
      userPublicKey,
    });
  }

  /**
   * Send document via SmartInvoice platform to the receiver
   * @param {String} receiverDID Decentralize identifier of the receiver
   * @param {File} file Document which should be sent
   * @param {Object} payload Additional information which should be attached to the document
   */
  sendTo(receiverDID, file, payload) {
    const self = this;
    self.encryptAndUploadDocument(file).then((response) => {
      const dri = response.data;
      self
        .encryptTransactionPayloadFor(receiverDID, dri, payload)
        .then((encryptedTransactionPayload) => {
          self.sendTransaction(
            self,
            encryptedTransactionPayload.encryptedMessage,
            encryptedTransactionPayload.encryptedSenderMessage,
            receiverDID,
          );
        });
    });
  }

  /**
   * Private method to upload file to decentralize storage and get DRI
   * Encrypt document and upload it to decentralize storage.
   * @param {File} file Document Blob
   * @return {Promise} axios promies and if success file Store DRI (decentralize resource identifier)
   */
  encryptAndUploadDocument(file) {
    let url = this.host;
    url += '/api/ddoc/upload';
    return axios.post(url, {
      encryptedFile: this.encryptWithAES(file),
    });
  }

  /**
   *
   * @param {String} receiverDID DID of the receiver
   * @param {String} fileStoreDRI File store DRI (Decentralize Resource Identifier) of encrypted document
   * @param {Object} payload JSON object with additional data
   * @return {Promise} promise with success result object with encryptedMessage for sender and recevier
   */
  encryptTransactionPayloadFor(receiverDID, fileStoreDRI, payload) {
    const { signKey } = this.identity.secret;
    const userKeyPair = sovrinDID.getKeyPairFromSignKey(signKey);

    return this.fetchIdentityFor(receiverDID).then((response) => {
      const sharedSecret = sovrinDID.getSharedSecret(
        response.data.publicKey,
        userKeyPair.secretKey,
      );

      // Encrypting for self transaction
      const sharedSecretSender = sovrinDID.getSharedSecret(
        userKeyPair.publicKey,
        userKeyPair.secretKey,
      );

      const transactionPayload = {
        aes: {
          aesSecret: this.aesSecret,
          aesIV: this.aesIv,
        },
        payload,
      };

      const message = JSON.stringify(transactionPayload);

      const encryptedMessage = sovrinDID.encryptMessage(message, this.nonce, sharedSecret);

      const encryptedSenderMessage = sovrinDID.encryptMessage(
        message,
        this.nonce,
        sharedSecretSender,
      );
      return { encryptedMessage, encryptedSenderMessage };
    });
  }

  /**
   * Decrypt payload from transaction
   * @param {String} senderDID Sender DID
   * @param {String} encryptedPayload encyprted payload from transaction
   * @return {Object} decrypted payload
   */
  decryptTransactionPayload(senderDID, encryptedPayload) {
    const { signKey } = this.identity.secret;
    const userKeyPair = sovrinDID.getKeyPairFromSignKey(signKey);
    return this.fetchIdentityFor(senderDID).then((response) => {
      const sharedSecret = sovrinDID.getSharedSecret(
        response.data.publicKey,
        userKeyPair.secretKey,
      );

      const payloadByteArray = Base64js.toByteArray(encryptedPayload);
      return sovrinDID.decryptMessage(payloadByteArray, this.nonce, sharedSecret);
    });
  }

  /**
   * Private method for encrypting the document with generated AES key
   * @param {File} unencryptedFile File blob to be encrypted
   */
  // eslint-disable-next-line class-methods-use-this
  encryptWithAES(unencryptedFile) {
    this.aesSecret = crypto.randomBytes(16).toString('hex');
    this.aesIv = crypto.randomBytes(16).toString('hex');
    const encryptedFile = CryptoJS.AES.encrypt(unencryptedFile, this.aesSecret, {
      key: this.aesIv,
    }).toString();
    return encryptedFile;
  }

  /**
   * Private method for encrypting the document with generated AES key
   * Decrypt give payload with given AES key
   * @param {String} encryptedFile Encrypted file
   * @return {String} Decrypted File
   */
  decryptWithAES(encryptedFile) {
    const bytes = CryptoJS.AES.decrypt(encryptedFile, this.aesSecret, {
      key: this.aesIv,
    });
    return bytes.toString(CryptoJS.enc.Utf8);
  }
}

import sovrinDID from 'sovrin-did';
import axios from 'axios';
import CryptoJS from 'crypto-js';
import crypto from 'crypto';
import Base64js from 'base64-js';

/**
 *
 * Main SmartInvoice class representing interface to Smart Invoice API endpoint. See below example how to use it:
 * <pre>
 *    var identity = SmartInvoice.createIdentity();
 *    var host = "https://api.difacturo.com"
 *    var config = { host: host}
 *    var smartinvoice = SmartInvoice.new(config, identity);
 * </pre>
 *
 * @constructor
 * @param {Object} instanceConfig Json object with configuration for new instance
 * @param {Identity} userIdentity Sovrin identity object generate with createIdentity()
 * @return SmartInvoice {object} - The top level SmartInvoice object
 * @license MIT
 */
class SmartInvoice {
  /**
   * Generate new DID base identity
   * It include public and private key. Currently supported only Sovrin but in the feature
   * this would be extended to other DID Methods.
   * @static
   * @return {Object} object including public and private key for the identity.
   */
  static createIdentity() {
    return sovrinDID.gen();
  }

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
   * Set/Get host for SmartInvoice API
   */
  set host(uri) {
    this.config.host = uri;
  }

  get host() {
    if (this.config === undefined || this.config.host === undefined) {
      throw Error('Host is not set check your config');
    }
    return this.config.host;
  }

  /**
   * Set/Get Json Web Token which is used to authenticate against endpoint from host variable
   * @param {String} JWT - json web token
   */
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
   * Login user and get JWT token for next calls
   * @async
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
   * @async
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
   * Allow to fetch document for the user within given time frame.
   *
   * @param {Timestamp} startTimestamp Miliseconds since 1900, from when we should get documents
   * @param {Timestamp} endTimestamp Miliseconds since 1900, until when we should look for documents
   */
  fetchDocuments(startTimestamp, endTimestamp) {
    let url = this.host;
    url += '/api/ddoc/transactions';
    return axios.get(url, {
      params: {
        startTimestamp,
        endTimestamp,
      },
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Send document via SmartInvoice platform to the receiver
   * @async
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
   * Encrypt transaction payload for given receiver.
   * In most cases you don't have to use it directly as
   * [sendTo]{@link SmartInvoice#sendTo} is taking care of it.
   * @async
   * @ignore
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
   * @async
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
   * @private
   * @ignore
   * @param {File} unencryptedFile File blob to be encrypted
   * @returns {String} encrypted file
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
   * @private
   * @ignore
   * @param {String} encryptedFile Encrypted file
   * @return {String} Decrypted File
   */
  decryptWithAES(encryptedFile) {
    const bytes = CryptoJS.AES.decrypt(encryptedFile, this.aesSecret, {
      key: this.aesIv,
    });
    return bytes.toString(CryptoJS.enc.Utf8);
  }

  /**
   * Fetch Public information about specific DID
   * @async
   * @private
   * @ignore
   * @param {String} did - Decentralized Identifier of the user.
   */
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
   * Private method to upload file to decentralize storage and get DRI
   * Encrypt document and upload it to decentralize storage.
   * @async
   * @ignore
   * @private
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
}

/**
 * <p>SmartInvoice module</p>
 *
 * <p>
 * SmartInvoice module allow you to interact with Smart Invoice network. See documentation for more details.
 * </p>
 * To include exported SmartInvoice class do this:
 * <pre>
 * import SmartInvoice from 'smartinvoice-sdk';
 * </pre>
 * or
 * <pre>
 * var SmartInvoice = require('smartinvoice-sdk');
 * </pre>
 * @module SmartInvoice
 */
export default SmartInvoice;

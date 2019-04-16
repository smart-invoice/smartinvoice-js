import sovrinDID from 'sovrin-did';
import axios from 'axios';
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
  constructor(instanceConfig) {
    this.config = instanceConfig;
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

  /**
   * Generate new DID base identity
   * It include public and private key. Currently supported only Sovrin but in the feature
   * this would be extended to other DID Methods.
   * @return {Object} object including public and private key for the identity.
   */
  static createIdentity() {
    return sovrinDID.gen();
  }

  /**
   * Login user and get JWT token for next calls
   * @param  {String} did User DID (Decentralize Identifier), currently only did:sov is supported
   * @param  {String} invitationCode The second number
   * @return {String} Json Web Token (JWT)
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

  register(apiEndpoint, publicKey, did, invitationCode) {
    let url = this.host;
    url += '/api/register?';
    return axios.get(url, {
      params: {
        invitationCode,
        orgEndpoint: apiEndpoint,
        userDID: did,
        userPublicKey: publicKey,
      },
    });
  }
}

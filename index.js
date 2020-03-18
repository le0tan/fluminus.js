const got = require('got').default;
const {CookieJar} = require('tough-cookie');

class Authorization {
  constructor(idsrv, jwt) {
    this.idsrv = idsrv;
    this.jwt = jwt;
  }
}

const REDIRECT_URI = 'https://luminus.nus.edu.sg/auth/callback';
const OCM_APIM_SUBSCRIPTION_KEY =
    '6963c200ca9440de8fa1eede730d8f7e';
const VAFS_CLIENT_ID =
    'E10493A3B1024F14BDC7D0D8B9F649E9-234390';
const RESOURCE = 'sg_edu_nus_oauth';
const API_BASE_URL = 'https://luminus.azure-api.net';

class Authentication {
  constructor(username, password) {
    this.username = username;
    this.password = password;
  }

  /**
   * Gets the object using credentials stored in this Authentication object.
   * @returns A Promise<Authorization> object.
   * @throws Will throw an error if connection is lost or credentials are invalid.
   */
  async getAuth() {
    return await this._getJwt(this.username, this.password);
  }

  async _getJwt() {
    // TODO: refresh jwt logic
    return await this._vafsJwt(this.username, this.password);
  }

  /**
   * Gets the JWT via VAFS.
   * @param {string} username 
   * @param {string} password 
   * @returns {Authorization} authorization
   */
  async _vafsJwt(username, password) {
    var query = {
      'response_type': 'code',
      'client_id': VAFS_CLIENT_ID,
      'resource': RESOURCE,
      'redirect_uri': REDIRECT_URI,
    };
    var body = {
      'UserName': username,
      'Password': password,
      'AuthMethod': 'FormsAuthentication'
    };
    var uri = new URL('/adfs/oauth2/authorize', 'https://vafs.nus.edu.sg');
    Object.keys(query).forEach((key) => {
      uri.searchParams.set(key, query[key]);
    });
    try {
      const cj = new CookieJar();
      const t1 = await got.post(uri.href, {followRedirect: false, form: body, cookieJar: cj});
      const loc1 = t1.headers['location'];
      const t2 = await got.get(loc1, {followRedirect: false, cookieJar: cj});
      const code = require('querystring').parse(require('url').parse(t2.headers['location']).query).code;
      const adfsBody = {
        'grant_type': 'authorization_code',
        'client_id': VAFS_CLIENT_ID,
        'resource': RESOURCE,
        'redirect_uri': REDIRECT_URI,
        'code': code
      };
      const t3 = await got.post(`${API_BASE_URL}/login/adfstoken`, {form: adfsBody, headers: {'Ocp-Apim-Subscription-Key': OCM_APIM_SUBSCRIPTION_KEY}});
      const access_token = JSON.parse(t3.body)['access_token'];
      return new Authorization('', access_token);
    } catch (error) {
      switch (error.name) {
        case 'RequestError':
          throw new Error("The connection to authentication server seems to be broken.");
        case 'TypeError':
          throw new Error("The provided credentials seem to be incorrect.")
        default:
          throw new Error("Unknown error when authenticating.")
      }
    }
  }
}

class Api {
  /**
   * 
   * @param {Authorization} auth 
   * @param {string} path 
   */
  static async _apiGet(auth, path) {
    const resp = await got.get(API_BASE_URL + path, {headers: {'Authorization': `Bearer ${auth.jwt}`, 'Ocp-Apim-Subscription-Key': OCM_APIM_SUBSCRIPTION_KEY}});
    return resp.body;
  }
}

module.exports = {
  Authentication,
  Api
}
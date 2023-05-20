import sha256 from 'crypto-js/sha256';
import Base64 from 'crypto-js/enc-base64';
import WordArray from 'crypto-js/lib-typedarrays';
import IAuthResponse from './IAuthResponse';
import IConfig from './IConfig';
import IObject from './IObject';
import ITokenResponse from './ITokenResponse';

export default class PKCE {
  private config: IConfig;
  private state: string = '';
  private codeVerifier: string = '';

  /**
   * Initialize the instance with configuration
   * @param {IConfig} config
   */
  constructor(config: IConfig) {
    this.config = config;
  }

  /**
   * Generate the authorize url
   * @param  {object} additionalParams include additional parameters in the query
   * @return Promise<string>
   */
  public async authorizeUrl(additionalParams: IObject = {}): Promise<string> {
    const codeChallenge = await this.pkceChallengeFromVerifier();

    const queryString = new URLSearchParams(
      Object.assign(
        {
          response_type: 'code',
          client_id: this.config.client_id,
          state: await this.getState(additionalParams.state || undefined),
          scope: this.config.requested_scopes,
          redirect_uri: this.config.redirect_uri,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
        },
        additionalParams,
      ),
    ).toString();

    return `${this.config.authorization_endpoint}?${queryString}`;
  }

  /**
   * Given the return url, get a token from the oauth server
   * @param  url current urlwith params from server
   * @param  {object} additionalParams include additional parameters in the request body
   * @return {Promise<ITokenResponse>}
   */
  public async exchangeForAccessToken(url: string, additionalParams: IObject = {}): Promise<ITokenResponse> {
    return fetch(this.config.token_endpoint, {
      method: 'POST',
      body: new URLSearchParams(
        Object.assign(
          {
            grant_type: 'authorization_code',
            code: (await this.parseAuthResponseUrl(url)).code,
            client_id: this.config.client_id,
            redirect_uri: this.config.redirect_uri,
            code_verifier: await this.getCodeVerifier(),
          },
          additionalParams,
        ),
      ),
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      },
    }).then((response) => response.json());
  }

  /**
   * Get the current codeVerifier or generate a new one
   * @return {string}
   */
  private async getCodeVerifier(): Promise<string> {
    if (this.codeVerifier === '') {
      this.codeVerifier = await this.randomStringFromStorage('pkce_code_verifier');
    }

    return this.codeVerifier;
  }

  /**
   * Get the current state or generate a new one
   * @return {string}
   */
  private async getState(explicit?: string): Promise<string> {
    const stateKey = 'pkce_state';

    if (explicit !== undefined) {
      await this.getStore().set({ stateKey: explicit });
    }

    if (this.state === '') {
      this.state = await this.randomStringFromStorage(stateKey);
    }

    return this.state;
  }

  /**
   * Get the query params as json from a auth response url
   * @param  {string} url a url expected to have AuthResponse params
   * @return {Promise<IAuthResponse>}
   */
  private parseAuthResponseUrl(url: string): Promise<IAuthResponse> {
    const params = new URL(url).searchParams;

    return this.validateAuthResponse({
      error: params.get('error'),
      query: params.get('query'),
      state: params.get('state'),
      code: params.get('code'),
    });
  }

  /**
   * Generate a code challenge
   * @return {Promise<string>}
   */
  private async pkceChallengeFromVerifier(): Promise<string> {
    const hashed = sha256(await this.getCodeVerifier());
    return Base64.stringify(hashed).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Get a random string from storage or store a new one and return it's value
   * @param  {string} key
   * @return {string}
   */
  private async randomStringFromStorage(key: string): Promise<string> {
    const fromStorage = this.getStore().get(key);
    if (key in fromStorage) {
      return fromStorage[key];
    } else {
      let k = WordArray.random(64).toString();
      await this.getStore().set({ key: k });
      return k;
    }
  }

  /**
   * Validates params from auth response
   * @param  {AuthResponse} queryParams
   * @return {Promise<IAuthResponse>}
   */
  private async validateAuthResponse(queryParams: IAuthResponse): Promise<IAuthResponse> {
    if (queryParams.error) {
      throw new Error(queryParams.error);
    }

    if (queryParams.state !== await this.getState()) {
      throw new Error('Invalid State');
    }

    return queryParams;
  }

  /**
   * Get the storage (sessionStorage / localStorage) to use, defaults to sessionStorage
   * @return {chrome.storage.StorageArea}
   */
  private getStore(): chrome.storage.StorageArea {
    return this.config?.storage || chrome.storage.session;
  }
}

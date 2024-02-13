/*
 *   Copyright OpenSearch Contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

import { httpServerMock } from '../../../../../../src/core/server/http/http_server.mocks';

import { OpenSearchDashboardsRequest } from '../../../../../../src/core/server/http/router';

import { OpenIdAuthentication } from './openid_auth';
import { SecurityPluginConfigType } from '../../../index';
import { SecuritySessionCookie } from '../../../session/security_cookie';
import { deflateValue } from '../../../utils/compression';
import { getObjectProperties } from '../../../utils/object_properties_defined';
import {
  IRouter,
  CoreSetup,
  ILegacyClusterClient,
  SessionStorageFactory,
} from '../../../../../../src/core/server';
import { BrowserSessionStorageFactory, SecurityAuthSessionStorageKey } from '../authentication_type.test';

jest.mock('./helper', () => ({
  ...jest.requireActual('./helper'),
  callTokenEndpoint: jest.fn().mockImplementation(() => {
    return {idToken:'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJSaHFsWXdKaTFXR1FJV0d6LUtsMklCUklDQTh0Y3loa1ZMdmk1eDZ2WmxRIn0.eyJleHAiOjkyMDg5NDQwMDAwMDAwfQ==.nsNfG5xxJWU24CcmgOBvJEKRKpoY81noHCO9_is4tLdX7grLz8HcQIFsrQaWTpPkIIbb7lc8FkYOlkwbnC9L5MX7lhfoJdPmG_Eh7uJl3RSIHm743gTmWmOeK8s5OPJnNibyfeUMpdH244jZ__uUchz3IrXKwt8pSvIKvGAFSgykkBtPghaePz4XOqNrOHvbP5bqKeoJGSSmHq_4b0bF0d_WQaPrQuduOJ545bTcfUJe38jWPPB1C4MywR1w1fzC0yg7DZFliPrLNXFwKSPd_CYwzLf1hwmr0vEd9I6QXAZo5BcAe9hVlX0mgZZ1H8FNqwvWd4rQKoDDnQMKs7NpsQ', refreshToken: 'blah'}
  }),
}));

jest.mock('../../session/cookie_splitter.ts', () => ({
  ...jest.requireActual('./helper'),
  callTokenEndpoint: jest.fn().mockImplementation(() => {
    return {idToken:'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJSaHFsWXdKaTFXR1FJV0d6LUtsMklCUklDQTh0Y3loa1ZMdmk1eDZ2WmxRIn0.eyJleHAiOjkyMDg5NDQwMDAwMDAwfQ==.nsNfG5xxJWU24CcmgOBvJEKRKpoY81noHCO9_is4tLdX7grLz8HcQIFsrQaWTpPkIIbb7lc8FkYOlkwbnC9L5MX7lhfoJdPmG_Eh7uJl3RSIHm743gTmWmOeK8s5OPJnNibyfeUMpdH244jZ__uUchz3IrXKwt8pSvIKvGAFSgykkBtPghaePz4XOqNrOHvbP5bqKeoJGSSmHq_4b0bF0d_WQaPrQuduOJ545bTcfUJe38jWPPB1C4MywR1w1fzC0yg7DZFliPrLNXFwKSPd_CYwzLf1hwmr0vEd9I6QXAZo5BcAe9hVlX0mgZZ1H8FNqwvWd4rQKoDDnQMKs7NpsQ', refreshToken: 'blah'}
  }),
}));

const mockedNow = 0;
Date.now = jest.fn(() => mockedNow);

class MockESClient {
  asScoped(request: OpenSearchDashboardsRequest) {
      return {
          async callAsCurrentUser(action: string, params: any) {
              // Dummy implementation, replace it with desired dummy value
              return { dummy: 'value' };
          }
      };
  }
}

interface Logger {
  debug(message: string): void;
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  fatal(message: string): void;
}

describe('test OpenId authHeaderValue', () => {
  let router: IRouter;
  let core: CoreSetup;
  let esClient: ILegacyClusterClient;
  let sessionStorageFactory: SessionStorageFactory<SecuritySessionCookie>;

  // Consistent with auth_handler_factory.test.ts
  beforeEach(() => {});

  const config = ({
    openid: {
      header: 'authorization',
      scope: [],
      extra_storage: {
        cookie_prefix: 'testcookie',
        additional_cookies: 5,
      },
    },
    auth: {
      unauthenticated_routes: []
    }
  } as unknown) as SecurityPluginConfigType;

  const logger = {
    debug: (message: string) => {},
    info: (message: string) => {},
    warn: (message: string) => {},
    error: (message: string) => {},
    fatal: (message: string) => {},
  };

  test('make sure that cookies with authHeaderValue are still valid', async () => {
    const openIdAuthentication = new OpenIdAuthentication(
      config,
      sessionStorageFactory,
      router,
      esClient,
      core,
      logger
    );

    const mockRequest = httpServerMock.createRawRequest();
    const osRequest = OpenSearchDashboardsRequest.from(mockRequest);

    const cookie: SecuritySessionCookie = {
      credentials: {
        authHeaderValue: 'Bearer eyToken',
      },
    };

    const expectedHeaders = {
      authorization: 'Bearer eyToken',
    };

    const headers = openIdAuthentication.buildAuthHeaderFromCookie(cookie, osRequest);

    expect(headers).toEqual(expectedHeaders);
  });

  test('get authHeaderValue from split cookies', async () => {
    const openIdAuthentication = new OpenIdAuthentication(
      config,
      sessionStorageFactory,
      router,
      esClient,
      core,
      logger
    );

    const testString = 'Bearer eyCombinedToken';
    const testStringBuffer: Buffer = deflateValue(testString);
    const cookieValue = testStringBuffer.toString('base64');
    const cookiePrefix = config.openid!.extra_storage.cookie_prefix;
    const splitValueAt = Math.ceil(
      cookieValue.length / config.openid!.extra_storage.additional_cookies
    );
    const mockRequest = httpServerMock.createRawRequest({
      state: {
        [cookiePrefix + '1']: cookieValue.substring(0, splitValueAt),
        [cookiePrefix + '2']: cookieValue.substring(splitValueAt),
      },
    });
    const osRequest = OpenSearchDashboardsRequest.from(mockRequest);

    const cookie: SecuritySessionCookie = {
      credentials: {
        authHeaderValueExtra: true,
      },
    };

    const expectedHeaders = {
      authorization: testString,
    };

    const headers = openIdAuthentication.buildAuthHeaderFromCookie(cookie, osRequest);

    expect(headers).toEqual(expectedHeaders);
  });

  test('Make sure that wreckClient can be configured with mTLS', async () => {
    const customConfig = {
      openid: {
        certificate: 'test/certs/cert.pem',
        private_key: 'test/certs/private-key.pem',
        header: 'authorization',
        scope: [],
      },
    };

    const openidConfig = (customConfig as unknown) as SecurityPluginConfigType;

    const openIdAuthentication = new OpenIdAuthentication(
      openidConfig,
      sessionStorageFactory,
      router,
      esClient,
      core,
      logger
    );

    const wreckHttpsOptions = openIdAuthentication.getWreckHttpsOptions();

    console.log(
      '============= PEM =============',
      '\n\n',
      getObjectProperties(customConfig.openid, 'OpenID'),
      '\n\n',
      getObjectProperties(wreckHttpsOptions, 'wreckHttpsOptions')
    );

    expect(wreckHttpsOptions.key).toBeDefined();
    expect(wreckHttpsOptions.cert).toBeDefined();
    expect(wreckHttpsOptions.pfx).toBeUndefined();
  });

  test('Ensure private key and certificate are not exposed when using PFX certificate', async () => {
    const customConfig = {
      openid: {
        pfx: 'test/certs/keyStore.p12',
        certificate: 'test/certs/cert.pem',
        private_key: 'test/certs/private-key.pem',
        passphrase: '',
        header: 'authorization',
        scope: [],
      },
    };

    const openidConfig = (customConfig as unknown) as SecurityPluginConfigType;

    const openIdAuthentication = new OpenIdAuthentication(
      openidConfig,
      sessionStorageFactory,
      router,
      esClient,
      core,
      logger
    );

    const wreckHttpsOptions = openIdAuthentication.getWreckHttpsOptions();

    console.log(
      '============= PFX =============',
      '\n\n',
      getObjectProperties(customConfig.openid, 'OpenID'),
      '\n\n',
      getObjectProperties(wreckHttpsOptions, 'wreckHttpsOptions')
    );

    expect(wreckHttpsOptions.pfx).toBeDefined();
    expect(wreckHttpsOptions.key).toBeUndefined();
    expect(wreckHttpsOptions.cert).toBeUndefined();
    expect(wreckHttpsOptions.passphrase).toBeUndefined();
  });

  test('OpenID cookie expiry time is based on IDP', async () => {
    const oidcConfig = ({
      openid: {
        header: 'authorization',
        scope: [],
        extra_storage: {
          cookie_prefix: 'testcookie',
          additional_cookies: 5,
        },
      },
      auth: {
        unauthenticated_routes: []
      },
      session:{
        keepalive: false
      }
    } as unknown) as SecurityPluginConfigType;
    const openIdAuthentication = new OpenIdAuthentication(
      oidcConfig,
      new BrowserSessionStorageFactory(SecurityAuthSessionStorageKey),
      router,
      new MockESClient(),
      core,
      logger
    );
    const cookie: SecuritySessionCookie = {
      credentials: {
        authHeaderValue: 'Bearer eyToken',
        refresh_token: 'blah'
      },
      username: 'admin',
      expiryTime: -1,
      authType: 'openid'
    };
    sessionStorage.setItem(SecurityAuthSessionStorageKey, JSON.stringify(cookie));

    const mockRequest = httpServerMock.createOpenSearchDashboardsRequest({
      path: '/api/v1',
    });

    // Mock response and toolkit functions
    const responseMock = jest.fn();
    const toolkitMock = {
      authenticated: jest.fn((value) => value),
    };

    const _ = await openIdAuthentication.authHandler(mockRequest, responseMock, toolkitMock);
    console.log(JSON.parse(sessionStorage.getItem(SecurityAuthSessionStorageKey)!))
  })
});

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
});

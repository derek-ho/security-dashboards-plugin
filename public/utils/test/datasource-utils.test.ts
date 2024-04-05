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

import {
  createDataSourceQuery,
  getClusterInfoIfEnabled,
  getDataSourceIdFromUrl,
  setDataSourceIdInUrl,
} from '../datasource-utils';

describe('Tests datasource utils', () => {
  it('Tests the GetClusterDescription helper function', () => {
    expect(getClusterInfoIfEnabled(false, { id: 'blah', label: 'blah' })).toBe('');
    expect(getClusterInfoIfEnabled(true, { id: '', label: '' })).toBe('for Local cluster');
    expect(getClusterInfoIfEnabled(true, { id: 'test', label: 'test' })).toBe('for test');
  });

  it('Tests the create DataSource query helper function', () => {
    expect(createDataSourceQuery('test')).toStrictEqual({ dataSourceId: 'test' });
  });

  it('Tests getting the datasource from the url', () => {
    const mockSearchNoDataSourceId = '?foo=bar&baz=qux';
    Object.defineProperty(window, 'location', {
      value: { search: mockSearchNoDataSourceId },
      writable: true,
    });
    expect(getDataSourceIdFromUrl()).toBe('');
    const mockSearchDataSourceIdNotfirst = '?foo=bar&baz=qux&dataSourceId=test';
    Object.defineProperty(window, 'location', {
      value: { search: mockSearchDataSourceIdNotfirst },
      writable: true,
    });
    expect(getDataSourceIdFromUrl()).toBe('test');
    const mockSearchDataSourceIdFirst = '?dataSourceId=test';
    Object.defineProperty(window, 'location', {
      value: { search: mockSearchDataSourceIdFirst },
      writable: true,
    });
    expect(getDataSourceIdFromUrl()).toBe('test');
  });

  it('Tests setting the datasource in the url', () => {
    const replaceState = jest.fn();
    const mockUrl = 'http://localhost:5601/app/security-dashboards-plugin#/auth';
    Object.defineProperty(window, 'location', {
      value: { href: mockUrl },
      writable: true,
    });
    Object.defineProperty(window, 'history', {
      value: { replaceState },
      writable: true,
    });
    setDataSourceIdInUrl('test');
    expect(replaceState).toBeCalledWith(
      {},
      '',
      'http://localhost:5601/app/security-dashboards-plugin?dataSourceId=test#/auth'
    );
  });
});

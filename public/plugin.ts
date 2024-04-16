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

import { BehaviorSubject } from 'rxjs';
import { SavedObjectsManagementColumn } from 'src/plugins/saved_objects_management/public';
import { i18n } from '@osd/i18n';
import {
  AppMountParameters,
  AppStatus,
  AppUpdater,
  CoreSetup,
  CoreStart,
  DEFAULT_APP_CATEGORIES,
  Plugin,
  PluginInitializerContext,
} from '../../../src/core/public';
import { APP_ID_LOGIN, CUSTOM_ERROR_PAGE_URI, LOGIN_PAGE_URI, PLUGIN_NAME } from '../common';
import { APP_ID_CUSTOMERROR } from '../common';
import { setupTopNavButton } from './apps/account/account-app';
import { fetchAccountInfoSafe } from './apps/account/utils';
import {
  API_ENDPOINT_PERMISSIONS_INFO,
  includeClusterPermissions,
  includeIndexPermissions,
} from './apps/configuration/constants';
import {
  excludeFromDisabledRestCategories,
  excludeFromDisabledTransportCategories,
} from './apps/configuration/panels/audit-logging/constants';
import {
  SecurityPluginStartDependencies,
  ClientConfigType,
  SecurityPluginSetup,
  SecurityPluginStart,
  SecurityPluginSetupDependencies,
} from './types';
import { addTenantToShareURL } from './services/shared-link';
import { interceptError } from './utils/logout-utils';
import { tenantColumn, getNamespacesToRegister } from './apps/configuration/utils/tenant-utils';
import { getDashboardsInfoSafe } from './utils/dashboards-info-utils';

async function hasApiPermission(core: CoreSetup): Promise<boolean | undefined> {
  try {
    const permissions = await core.http.get(API_ENDPOINT_PERMISSIONS_INFO);
    return permissions.has_api_access || false;
  } catch (e) {
    console.error(e);
    // ignore exceptions and default to no security related access.
    return false;
  }
}

export class SecurityPlugin
  implements
    Plugin<
      SecurityPluginSetup,
      SecurityPluginStart,
      SecurityPluginSetupDependencies,
      SecurityPluginStartDependencies
    > {
  // @ts-ignore : initializerContext not used
  constructor(private readonly initializerContext: PluginInitializerContext) {}

  public async setup(
    core: CoreSetup,
    deps: SecurityPluginSetupDependencies
  ): Promise<SecurityPluginSetup> {
    const config = this.initializerContext.config.get<ClientConfigType>();

    core.application.register({
      id: PLUGIN_NAME,
      title: 'Security',
      order: 9050,
      mount: async (params: AppMountParameters) => {
        const { renderApp } = await import('./apps/configuration/configuration-app');
        const [coreStart, depsStart] = await core.getStartServices();

        // merge OpenSearchDashboards yml configuration
        includeClusterPermissions(config.clusterPermissions.include);
        includeIndexPermissions(config.indexPermissions.include);

        excludeFromDisabledTransportCategories(config.disabledTransportCategories.exclude);
        excludeFromDisabledRestCategories(config.disabledRestCategories.exclude);

        return renderApp(coreStart, depsStart as SecurityPluginStartDependencies, params, config);
      },
      category: DEFAULT_APP_CATEGORIES.management,
    });

    if (deps.managementOverview) {
      deps.managementOverview.register({
        id: PLUGIN_NAME,
        title: 'Security',
        order: 9050,
        description: i18n.translate('security.securityDescription', {
          defaultMessage:
            'Configure how users access data in OpenSearch with authentication, access control and audit logging.',
        }),
      });
    }

    // Return methods that should be available to other plugins
    return {};
  }

  public start(core: CoreStart, deps: SecurityPluginStartDependencies): SecurityPluginStart {
    return {};
  }

  public stop() {}
}

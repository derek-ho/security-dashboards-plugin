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

import { DataSourceManagementPluginSetup } from '../../../../src/plugins/data_source_management/public';
import { AppMountParameters, CoreStart } from '../../../../src/core/public';
import { SecurityPluginStartDependencies, ClientConfigType, DashboardsInfo } from '../types';

export interface AppDependencies {
  coreStart: CoreStart;
  securityPluginStartDeps: SecurityPluginStartDependencies;
  params: AppMountParameters;
  config: ClientConfigType;
  dashboardsInfo: DashboardsInfo;
  setHeaderActionMenu: AppMountParameters['setHeaderActionMenu'];
  dataSourceManagement: DataSourceManagementPluginSetup;
}

export interface BreadcrumbsPageDependencies extends AppDependencies {
  buildBreadcrumbs: (pageTitle: string, subAction?: string) => void;
}

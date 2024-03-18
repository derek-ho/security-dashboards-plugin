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
import { ADMIN_AUTH } from '../../support/constants';

Cypress.Commands.overwrite('visit', (orig, url, options = {}) => {
  if (Cypress.env('LOGIN_AS_ADMIN')) {
    options.auth = ADMIN_AUTH;
  }
  orig(url, options);
});

const createDataSource = () => {
  cy.visit('http://localhost:5601/app/management/opensearch-dashboards/dataSources/create', {
    failOnStatusCode: false,
  });
  cy.get('[data-test-subj="createDataSourceFormTitleField"]').focus().type('9202');
  cy.get('[data-test-subj="createDataSourceFormEndpointField"]')
    .focus()
    .type('http://localhost:9202');
  cy.get('[data-test-subj="createDataSourceFormUsernameField"]').focus().type('admin');
  cy.get('[data-test-subj="createDataSourceFormPasswordField"]')
    .focus()
    .type('myStrongPassword123!');
  cy.get('[data-test-subj="createDataSourceTestConnectionButton"]').click();
  cy.get('.euiToastHeader__title').should('contain', 'successful');
  cy.get('[data-test-subj="createDataSourceButton"]').click({ force: true });
  // Wait for dataSource to be created
  cy.url().should('eq', 'http://localhost:5601/app/management/opensearch-dashboards/dataSources');
};

const deleteAllDataSources = () => {
  cy.visit('http://localhost:5601/app/management/opensearch-dashboards/dataSources');
  cy.get('[data-test-subj="checkboxSelectAll"]').click();
  cy.get('[data-test-subj="deleteDataSourceConnections"]').click();
  cy.get('[data-test-subj="confirmModalConfirmButton"]').click();
};

describe('Multi-datasources enabled', () => {
  before(() => {
    localStorage.setItem('opendistro::security::tenant::saved', '""');
    localStorage.setItem('home:newThemeModal:show', 'false');
    createDataSource();
  });

  after(() => {
    deleteAllDataSources();
    cy.clearLocalStorage();
  });

  it('Checks Get Started Tab', () => {
    cy.visit('http://localhost:5601/app/security-dashboards-plugin#/getstarted');
    // Local cluster purge cache
    cy.get('[data-test-subj="purge-cache"]').click();
    cy.get('.euiToastHeader__title').should('contain', 'successful for Local cluster');
    // Remote cluster purge cache
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').click();
    cy.contains('li.euiSelectableListItem', '9202').click();
    cy.get('[data-test-subj="purge-cache"]').click();
    cy.get('.euiToastHeader__title').should('contain', 'successful for 9202');
  });
});

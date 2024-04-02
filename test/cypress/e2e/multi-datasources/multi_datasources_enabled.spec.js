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

const createDataSource = () => {
  cy.request({
    method: 'POST',
    url: `${Cypress.config('baseUrl')}/api/saved_objects/data-source`,
    headers: {
      'osd-xsrf': true,
    },
    body: {
      attributes: {
        title: '9202',
        endpoint: 'https://localhost:9202',
        auth: {
          type: 'username_password',
          credentials: {
            username: 'admin',
            password: 'myStrongPassword123!',
          },
        },
      },
    },
  });
};

const closeToast = () => {
  // remove browser incompatibiltiy toast causing flakyness (cause it has higher z-index than Create button making it invisible)
  cy.get('body').then((body) => {
    if (body.find('[data-test-subj="toastCloseButton"]').length > 0) {
      cy.get('[data-test-subj="toastCloseButton"]').click();
    }
  });
};

const deleteAllDataSources = () => {
  cy.request(
    'GET',
    `${Cypress.config(
      'baseUrl'
    )}/api/saved_objects/_find?fields=id&fields=description&fields=title&per_page=10000&type=data-source`
  ).then((resp) => {
    if (resp && resp.body && resp.body.saved_objects) {
      resp.body.saved_objects.map(({ id }) => {
        cy.request({
          method: 'DELETE',
          url: `${Cypress.config('baseUrl')}/api/saved_objects/data-source/${id}`,
          body: { force: false },
          headers: {
            'osd-xsrf': true,
          },
        });
      });
    }
  });
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
    cy.get('[title="9202"]').click();
    cy.get('[data-test-subj="purge-cache"]').click();
    cy.get('.euiToastHeader__title').should('contain', 'successful for 9202');
    cy.visit('http://localhost:5601/app/security-dashboards-plugin#/auth');
    // Data source persisted across tabs
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').contains('9202');
  });

  it('Checks Auth Tab', () => {
    cy.visit('http://localhost:5601/app/security-dashboards-plugin#/auth');
    // Local cluster auth
    cy.get('.panel-header-count').first().invoke('text').should('contain', '(6)');
    // Remote cluster auth
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').click();
    cy.get('[title="9202"]').click();
    cy.get('.panel-header-count').first().invoke('text').should('contain', '(6)');
  });

  it('Checks Users Tab', () => {
    cy.visit('http://localhost:5601/app/security-dashboards-plugin#/users');
    // Create an internal user in the remote cluster
    cy.contains('h3', 'Internal users');
    cy.contains('a', 'admin');

    closeToast();

    // select remote data source
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').click();
    cy.get('[title="9202"]').click();

    // create a user on remote data source
    cy.get('[data-test-subj="create-user"]').click();
    cy.get('[data-test-subj="name-text"]').focus().type('9202-user');
    cy.get('[data-test-subj="password"]').focus().type('myStrongPassword123!');
    cy.get('[data-test-subj="re-enter-password"]').focus().type('myStrongPassword123!');
    cy.get('[data-test-subj="submit-save-user"]').click();

    // Internal user exists on the remote
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').should(
      'contain',
      '9202'
    );
    cy.get('[data-test-subj="checkboxSelectRow-9202-user"]').should('exist');

    // Internal user doesn't exist on local cluster
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').click();
    cy.get('[title="Local cluster"]').click();
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').should(
      'contain',
      'Local cluster'
    );
    cy.get('[data-test-subj="checkboxSelectRow-9202-user"]').should('not.exist');
  });

  it('Checks Permissions Tab', () => {
    cy.visit('http://localhost:5601/app/security-dashboards-plugin#/permissions');
    // Create a permission in the remote cluster
    cy.contains('h3', 'Permissions');

    closeToast();

    // Select remote cluster
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').click();
    cy.get('[title="9202"]').click();
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').should(
      'contain',
      '9202'
    );

    // Create an action group
    cy.get('[id="Create action group"]').click();
    cy.get('[id="create-from-blank"]').click();
    cy.get('[data-test-subj="name-text"]')
      .focus()
      .type('test_permission_ag', { force: true })
      .should('have.value', 'test_permission_ag');
    cy.get('[data-test-subj="comboBoxInput"]').focus().type('some_permission');
    cy.get('[id="submit"]').click();

    // Permission exists on the remote data source
    cy.get('[data-text="Customization"]').click();
    cy.get('[data-test-subj="filter-custom-action-groups"]').click();
    cy.get('[data-test-subj="checkboxSelectRow-test_permission_ag"]').should('exist');

    // Permission doesn't exist on local cluster
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').click();
    cy.get('[title="Local cluster"]').click();
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').should(
      'contain',
      'Local cluster'
    );
    cy.get('[data-test-subj="checkboxSelectRow-test_permission_ag"]').should('not.exist');
  });

  it('Checks Tenancy Tab', () => {
    // Datasource is locked to local cluster for tenancy tab
    cy.visit('http://localhost:5601/app/security-dashboards-plugin#/tenants');
    cy.contains('h1', 'Multi-tenancy');
    cy.get('[data-test-subj="dataSourceViewContextMenuHeaderLink"]').should(
      'contain',
      'Local cluster'
    );
    cy.get('[data-test-subj="dataSourceViewContextMenuHeaderLink"]').should('be.disabled');
  });

  it('Checks Audit Logs Tab', () => {
    cy.visit('http://localhost:5601/app/security-dashboards-plugin#/auditLogging');
    cy.get('[data-test-subj="general-settings"]').should('exist');

    // Select remote cluster
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').click();
    cy.get('[title="9202"]').click();
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').should(
      'contain',
      '9202'
    );

    cy.get('[data-test-subj="general-settings-configure"]').click();
    cy.get('[data-test-subj="dataSourceViewContextMenuHeaderLink"]').should('contain', '9202');

    cy.get('[data-test-subj="comboBoxInput"]').last().type('blah');
    cy.get('[data-test-subj="save"]').click();

    cy.get('[data-test-subj="general-settings"]').should('contain', 'blah');

    // Select local cluster
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').click();
    cy.get('[title="Local cluster"]').click();
    cy.get('[data-test-subj="dataSourceSelectableContextMenuHeaderLink"]').should(
      'contain',
      'Local cluster'
    );

    cy.get('[data-test-subj="general-settings"]').should('not.contain', 'blah');
  });
});

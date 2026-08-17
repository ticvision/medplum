// SPDX-FileCopyrightText: Copyright Orangebot, Inc. and Medplum contributors
// SPDX-License-Identifier: Apache-2.0
import type { WithId } from '@medplum/core';
import { ContentType, createReference } from '@medplum/core';
import type { AccessPolicy, ClientApplication, Project, ProjectMembership } from '@medplum/fhirtypes';
import { randomUUID } from 'crypto';
import express from 'express';
import request from 'supertest';
import { vi } from 'vitest';
import { createClient } from '../admin/client';
import { inviteUser } from '../admin/invite';
import { initApp, shutdownApp } from '../app';
import { loadTestConfig } from '../config/loader';
import type { MedplumServerConfig } from '../config/types';
import { CORAL_EXCHANGE_POLICY_NAME } from '../fhir/coralexchangeauthority';
import { getGlobalSystemRepo, getProjectSystemRepo } from '../fhir/repo';
import { withTestContext } from '../test.setup';
import { mockFetchJson, mockFetchText } from '../test.setup.fetch';
import { registerNew } from './register';

const fetchMock = vi.spyOn(globalThis, 'fetch');

const app = express();
const domain = randomUUID() + '.example.com';
const email = `text@${domain}`;
const redirectUri = `https://${domain}/auth/callback`;
const externalId = `google-oauth2|${randomUUID()}`;
const externalAuthIssuer = 'https://example.com';
const identityProvider = {
  authorizeUrl: 'https://example.com/oauth2/authorize',
  tokenUrl: 'https://example.com/oauth2/token',
  userInfoUrl: 'https://example.com/oauth2/userinfo',
  clientId: '123',
  clientSecret: '456',
};
const gcipIdentityProvider = {
  ...identityProvider,
  userInfoUrl: 'https://identitytoolkit.googleapis.com/v1/accounts:lookup',
  userInfoMode: 'gcip' as const,
  userInfoApiKey: 'test-api-key',
};
let config: MedplumServerConfig;
let project: WithId<Project>;
let defaultClient: ClientApplication;
let externalAuthClient: ClientApplication;
let subjectAuthClient: ClientApplication;
let gcipAuthClient: ClientApplication;
let gcipSubjectAuthClient: ClientApplication;
let serverExternalAuthClient: ClientApplication;

describe('Token Exchange', () => {
  beforeAll(async () => {
    config = await loadTestConfig();
    await withTestContext(async () => {
      await initApp(app, config);

      // Create a new project
      const registration = await registerNew({
        firstName: 'External',
        lastName: 'Text',
        projectName: 'External Test Project',
        email,
        password: 'password!@#',
        remoteAddress: '5.5.5.5',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/107.0.0.0',
      });
      project = registration.project;
      defaultClient = registration.client;

      const systemRepo = await getProjectSystemRepo(project);

      // Create a new client application with external auth
      externalAuthClient = await createClient(systemRepo, {
        project,
        name: 'External Auth Client',
        redirectUri,
        identityProvider,
      });

      // Create a new client application with external subject auth
      subjectAuthClient = await createClient(systemRepo, {
        project,
        name: 'Subject Auth Client',
        redirectUri,
      });

      // Update client application with external auth
      await systemRepo.updateResource<ClientApplication>({
        ...subjectAuthClient,
        identityProvider: {
          ...identityProvider,
          useSubject: true,
        },
      });

      gcipAuthClient = await createClient(systemRepo, {
        project,
        name: 'GCIP Auth Client',
        redirectUri,
        identityProvider: gcipIdentityProvider,
      });

      gcipSubjectAuthClient = await createClient(systemRepo, {
        project,
        name: 'GCIP Subject Auth Client',
        redirectUri,
        identityProvider: {
          ...gcipIdentityProvider,
          useSubject: true,
        },
      });
      const exchangeSystemRepo = getGlobalSystemRepo();
      const serverExternalAuthProject = await exchangeSystemRepo.createResource<Project>({
        resourceType: 'Project',
        name: 'Server external auth authority',
        strictMode: true,
        superAdmin: false,
      });
      serverExternalAuthClient = await exchangeSystemRepo.createResource<ClientApplication>({
        resourceType: 'ClientApplication',
        status: 'active',
        secret: randomUUID(),
        meta: { project: serverExternalAuthProject.id },
      });
      const serverExternalAuthPolicy = await exchangeSystemRepo.createResource<AccessPolicy>({
        resourceType: 'AccessPolicy',
        meta: { project: serverExternalAuthProject.id },
        name: CORAL_EXCHANGE_POLICY_NAME,
        resource: [],
      });
      await exchangeSystemRepo.createResource<ProjectMembership>({
        resourceType: 'ProjectMembership',
        user: createReference(serverExternalAuthClient),
        profile: createReference(serverExternalAuthClient),
        project: createReference(serverExternalAuthProject),
        accessPolicy: createReference(serverExternalAuthPolicy),
        active: true,
        admin: false,
      });

      // Invite user with external ID
      await inviteUser({
        project,
        externalId,
        resourceType: 'Patient',
        firstName: 'External',
        lastName: 'User',
      });
    });
  });

  afterEach(() => {
    fetchMock.mockClear();
    config.externalAuthProviders = undefined;
  });

  afterAll(async () => {
    await shutdownApp();
  });

  test('Missing externalAccessToken', async () => {
    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: '',
      clientId: defaultClient.id,
      clientSecret: defaultClient.secret,
    });
    expect(res).toHaveStatus(400);
    expect(res.body.issue[0].details.text).toBe('Missing externalAccessToken');
  });

  test('Missing clientId', async () => {
    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'xyz',
      clientId: '',
      clientSecret: defaultClient.secret,
    });
    expect(res).toHaveStatus(400);
    expect(res.body.issue[0].details.text).toBe('Missing clientId');
  });

  test('Missing clientSecret', async () => {
    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'xyz',
      clientId: externalAuthClient.id,
      clientSecret: '',
    });
    expect(res).toHaveStatus(400);
    expect(res.body.issue[0].details.text).toBe('Missing clientSecret');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('Missing identity provider', async () => {
    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'xyz',
      clientId: defaultClient.id,
      clientSecret: defaultClient.secret,
    });
    expect(res).toHaveStatus(400);
    expect(res.body.error_description).toBe('Invalid client');
  });

  test('Unknown user', async () => {
    fetchMock.mockImplementation(() => mockFetchJson({ email: 'not-found@' + domain }));

    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'xyz',
      clientId: externalAuthClient.id,
      clientSecret: externalAuthClient.secret,
    });
    expect(res).toHaveStatus(400);
    expect(res.body.issue[0].details.text).toBe('User not found');
  });

  test('ClientApplication success', async () => {
    fetchMock.mockImplementation(() => mockFetchJson({ email }));

    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'xyz',
      clientId: externalAuthClient.id,
      clientSecret: externalAuthClient.secret,
    });
    expect(res).toHaveStatus(200);
    expect(res.body.access_token).toBeTruthy();
  });

  test('Server external auth provider success', async () => {
    config.externalAuthProviders = [
      { issuer: externalAuthIssuer, clientId: serverExternalAuthClient.id, identityProvider },
    ];

    fetchMock.mockImplementation(() => mockFetchJson({ email }));

    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'xyz',
      clientId: serverExternalAuthClient.id,
      clientSecret: serverExternalAuthClient.secret,
    });
    expect(res).toHaveStatus(200);
    expect(res.body.access_token).toBeTruthy();
  });

  test('GCIP success', async () => {
    fetchMock.mockImplementation(() => mockFetchJson({ users: [{ email, localId: 'firebase-user-id' }] }));

    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'firebase-token',
      clientId: gcipAuthClient.id,
      clientSecret: gcipAuthClient.secret,
    });
    expect(res).toHaveStatus(200);
    expect(res.body.access_token).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=test-api-key',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Accept: ContentType.JSON,
          'Content-Type': ContentType.JSON,
        }),
        body: JSON.stringify({ idToken: 'firebase-token' }),
      })
    );
    const fetchUrl = fetchMock.mock.calls.at(-1)?.[0];
    expect(typeof fetchUrl).toBe('string');
    expect(new URL(fetchUrl as string).searchParams.get('key')).toBe('test-api-key');
  });

  test('Missing projectId success', async () => {
    fetchMock.mockImplementation(() => mockFetchJson({ email }));

    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'xyz',
      projectId: '',
      clientId: externalAuthClient.id,
      clientSecret: externalAuthClient.secret,
    });
    expect(res).toHaveStatus(200);
  });

  test('Invalid token request', async () => {
    fetchMock.mockImplementation(() => mockFetchText('', { contentType: ContentType.TEXT }));

    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'xyz',
      clientId: externalAuthClient.id,
      clientSecret: externalAuthClient.secret,
    });
    expect(res).toHaveStatus(400);
    expect(res.body.error).toBe('invalid_request');
    expect(res.body.error_description).toBe('Failed to verify code - unsupported content type: text/plain');
  });

  test('Subject auth success', async () => {
    fetchMock.mockImplementation(() => mockFetchJson({ email: '', sub: externalId }));

    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'xyz',
      clientId: subjectAuthClient.id,
      clientSecret: subjectAuthClient.secret,
    });
    expect(res).toHaveStatus(200);
    expect(res.body.access_token).toBeTruthy();
  });

  test('GCIP subject auth success', async () => {
    fetchMock.mockImplementation(() => mockFetchJson({ users: [{ email: '', localId: externalId }] }));

    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'firebase-token',
      clientId: gcipSubjectAuthClient.id,
      clientSecret: gcipSubjectAuthClient.secret,
    });
    expect(res).toHaveStatus(200);
    expect(res.body.access_token).toBeTruthy();
  });

  test('GCIP missing localId', async () => {
    fetchMock.mockImplementation(() => mockFetchJson({ users: [{ email }] }));

    const res = await request(app).post('/auth/exchange').type('json').send({
      externalAccessToken: 'firebase-token',
      clientId: gcipAuthClient.id,
      clientSecret: gcipAuthClient.secret,
    });
    expect(res).toHaveStatus(400);
    expect(res.body.error_description).toBe('Failed to verify code - missing localId in user info response');
  });
});

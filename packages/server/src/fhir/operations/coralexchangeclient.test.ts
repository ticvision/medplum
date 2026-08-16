// SPDX-FileCopyrightText: Copyright Orangebot, Inc. and Medplum contributors
// SPDX-License-Identifier: Apache-2.0
import { ContentType, Operator, createReference, getStatus, normalizeOperationOutcome } from '@medplum/core';
import type { AccessPolicy, ClientApplication, Project, ProjectMembership } from '@medplum/fhirtypes';
import express from 'express';
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { initApp, shutdownApp } from '../../app';
import { loadTestConfig } from '../../config/loader';
import { createTestProject, initTestAuth, withTestContext } from '../../test.setup';
import { getGlobalSystemRepo } from '../repo';
import {
  CORAL_EXCHANGE_CLIENT_ID,
  CORAL_EXCHANGE_MEMBERSHIP_ID,
  CORAL_EXCHANGE_POLICY_ID,
  CORAL_EXCHANGE_PROJECT_ID,
  readCoralExchangeClientState,
  stageCoralExchangeClientResources,
  transitionCoralExchangeClientResources,
} from './coralexchangeclient';

const SECRET = 'SyntheticExchangeClientSecret01234567890123456789012345678901234';
const app = express();

describe('stageCoralExchangeClientResources', () => {
  beforeAll(async () => {
    await initApp(app, await loadTestConfig());
  });

  afterAll(async () => {
    await shutdownApp();
  });

  beforeEach(async () => {
    await withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();
      const memberships = await systemRepo.searchResources<ProjectMembership>({
        resourceType: 'ProjectMembership',
        filters: [
          {
            code: 'user',
            operator: Operator.EQUALS,
            value: `ClientApplication/${CORAL_EXCHANGE_CLIENT_ID}`,
          },
        ],
      });
      for (const membership of memberships) {
        await systemRepo.deleteResource('ProjectMembership', membership.id);
      }
      for (const [resourceType, id] of [
        ['ClientApplication', CORAL_EXCHANGE_CLIENT_ID],
        ['AccessPolicy', CORAL_EXCHANGE_POLICY_ID],
        ['Project', CORAL_EXCHANGE_PROJECT_ID],
      ] as const) {
        await systemRepo.deleteResource(resourceType, id).catch(() => undefined);
      }
    });
  });

  test('atomically stages one fixed off client with an inactive deny-all membership', () =>
    withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();

      await stageCoralExchangeClientResources(systemRepo, SECRET);

      const project = await systemRepo.readResource<Project>('Project', CORAL_EXCHANGE_PROJECT_ID);
      const policy = await systemRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      const client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      const membership = await systemRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );
      expect(project).toMatchObject({
        name: 'Coral confidential exchange control',
        strictMode: true,
        superAdmin: false,
      });
      expect(policy).toMatchObject({
        meta: { project: project.id },
        name: 'Coral confidential token exchange deny all',
      });
      expect(policy.resource ?? []).toEqual([]);
      expect(client).toMatchObject({
        meta: { project: project.id },
        status: 'off',
        secret: SECRET,
      });
      expect(client.retiringSecret).toBeUndefined();
      expect(membership).toMatchObject({
        active: false,
        admin: false,
        user: createReference(client),
        profile: createReference(client),
        project: createReference(project),
        accessPolicy: createReference(policy),
      });
      expect(membership.access).toBeUndefined();
      expect({
        projectDefaultPatientPolicy: project.defaultPatientAccessPolicy,
        projectDefaultPolicies: project.defaultAccessPolicies,
        policyBasedOn: policy.basedOn,
        policyCompartment: policy.compartment,
        policyIpRules: policy.ipAccessRule,
        clientIdentityProvider: client.identityProvider,
        clientJwksUri: client.jwksUri,
        clientRedirectUris: client.redirectUris,
        clientRedirectUri: client.redirectUri,
        clientAllowedOrigin: client.allowedOrigin,
        clientTrustStore: client.certificateTrustStore,
      }).toEqual({
        projectDefaultPatientPolicy: undefined,
        projectDefaultPolicies: undefined,
        policyBasedOn: undefined,
        policyCompartment: undefined,
        policyIpRules: undefined,
        clientIdentityProvider: undefined,
        clientJwksUri: undefined,
        clientRedirectUris: undefined,
        clientRedirectUri: undefined,
        clientAllowedOrigin: undefined,
        clientTrustStore: undefined,
      });
    }));

  test('atomically activates the exact staged authority snapshot', () =>
    withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();
      await stageCoralExchangeClientResources(systemRepo, SECRET);
      const project = await systemRepo.readResource<Project>('Project', CORAL_EXCHANGE_PROJECT_ID);
      const policy = await systemRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      const client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      const membership = await systemRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );

      await transitionCoralExchangeClientResources(systemRepo, {
        action: 'activate',
        projectVersionId: project.meta?.versionId as string,
        policyVersionId: policy.meta?.versionId as string,
        clientVersionId: client.meta?.versionId as string,
        membershipVersionId: membership.meta?.versionId as string,
        clientSecret: SECRET,
      });

      expect(
        await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID)
      ).toMatchObject({ status: 'active' });
      expect(
        await systemRepo.readResource<ProjectMembership>('ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID)
      ).toMatchObject({ active: true, admin: false });
    }));

  test('rejects a stale activation snapshot without changing either active flag', () =>
    withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();
      await stageCoralExchangeClientResources(systemRepo, SECRET);
      const project = await systemRepo.readResource<Project>('Project', CORAL_EXCHANGE_PROJECT_ID);
      const policy = await systemRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      const membership = await systemRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );

      let failure: unknown;
      try {
        await transitionCoralExchangeClientResources(systemRepo, {
          action: 'activate',
          projectVersionId: project.meta?.versionId as string,
          policyVersionId: policy.meta?.versionId as string,
          clientVersionId: randomUUID(),
          membershipVersionId: membership.meta?.versionId as string,
          clientSecret: SECRET,
        });
      } catch (error) {
        failure = error;
      }

      expect(getStatus(normalizeOperationOutcome(failure))).toBe(412);
      expect(
        await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID)
      ).toMatchObject({ status: 'off' });
      expect(
        await systemRepo.readResource<ProjectMembership>('ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID)
      ).toMatchObject({ active: false });
    }));

  test('rejects a current snapshot whose empty policy gained authority', () =>
    withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();
      await stageCoralExchangeClientResources(systemRepo, SECRET);
      const project = await systemRepo.readResource<Project>('Project', CORAL_EXCHANGE_PROJECT_ID);
      const stagedPolicy = await systemRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      const policy = await systemRepo.updateResource<AccessPolicy>({
        ...stagedPolicy,
        resource: [{ resourceType: 'Patient', interaction: ['read'] }],
      });
      const client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      const membership = await systemRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );

      let failure: unknown;
      try {
        await transitionCoralExchangeClientResources(systemRepo, {
          action: 'activate',
          projectVersionId: project.meta?.versionId as string,
          policyVersionId: policy.meta?.versionId as string,
          clientVersionId: client.meta?.versionId as string,
          membershipVersionId: membership.meta?.versionId as string,
          clientSecret: SECRET,
        });
      } catch (error) {
        failure = error;
      }

      expect(getStatus(normalizeOperationOutcome(failure))).toBe(400);
      expect(
        await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID)
      ).toMatchObject({ status: 'off' });
      expect(
        await systemRepo.readResource<ProjectMembership>('ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID)
      ).toMatchObject({ active: false });
    }));

  test('rejects a staged client with more than one membership', () =>
    withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();
      await stageCoralExchangeClientResources(systemRepo, SECRET);
      const project = await systemRepo.readResource<Project>('Project', CORAL_EXCHANGE_PROJECT_ID);
      const policy = await systemRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      const client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      const membership = await systemRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );
      await systemRepo.createResource<ProjectMembership>({
        resourceType: 'ProjectMembership',
        id: randomUUID(),
        user: createReference(client),
        profile: createReference(client),
        project: createReference(project),
        accessPolicy: createReference(policy),
        active: false,
        admin: false,
      });

      let failure: unknown;
      try {
        await transitionCoralExchangeClientResources(systemRepo, {
          action: 'activate',
          projectVersionId: project.meta?.versionId as string,
          policyVersionId: policy.meta?.versionId as string,
          clientVersionId: client.meta?.versionId as string,
          membershipVersionId: membership.meta?.versionId as string,
          clientSecret: SECRET,
        });
      } catch (error) {
        failure = error;
      }

      expect(getStatus(normalizeOperationOutcome(failure))).toBe(400);
      expect(
        await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID)
      ).toMatchObject({ status: 'off' });
    }));

  test('atomically restages the exact active authority snapshot', () =>
    withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();
      await stageCoralExchangeClientResources(systemRepo, SECRET);
      const project = await systemRepo.readResource<Project>('Project', CORAL_EXCHANGE_PROJECT_ID);
      const policy = await systemRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      let client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      let membership = await systemRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );
      await transitionCoralExchangeClientResources(systemRepo, {
        action: 'activate',
        projectVersionId: project.meta?.versionId as string,
        policyVersionId: policy.meta?.versionId as string,
        clientVersionId: client.meta?.versionId as string,
        membershipVersionId: membership.meta?.versionId as string,
        clientSecret: SECRET,
      });
      client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      membership = await systemRepo.readResource<ProjectMembership>('ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID);

      await transitionCoralExchangeClientResources(systemRepo, {
        action: 'restage',
        projectVersionId: project.meta?.versionId as string,
        policyVersionId: policy.meta?.versionId as string,
        clientVersionId: client.meta?.versionId as string,
        membershipVersionId: membership.meta?.versionId as string,
        clientSecret: SECRET,
      });

      expect(
        await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID)
      ).toMatchObject({ status: 'off' });
      expect(
        await systemRepo.readResource<ProjectMembership>('ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID)
      ).toMatchObject({ active: false, admin: false });
    }));

  test('verifies the exact active authority without changing any resource version', async () => {
    let versions: Record<string, string> = {};
    await withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();
      await stageCoralExchangeClientResources(systemRepo, SECRET);
      const project = await systemRepo.readResource<Project>('Project', CORAL_EXCHANGE_PROJECT_ID);
      const policy = await systemRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      let client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      let membership = await systemRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );
      await transitionCoralExchangeClientResources(systemRepo, {
        action: 'activate',
        projectVersionId: project.meta?.versionId as string,
        policyVersionId: policy.meta?.versionId as string,
        clientVersionId: client.meta?.versionId as string,
        membershipVersionId: membership.meta?.versionId as string,
        clientSecret: SECRET,
      });
      client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      membership = await systemRepo.readResource<ProjectMembership>('ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID);
      versions = {
        projectVersionId: project.meta?.versionId as string,
        policyVersionId: policy.meta?.versionId as string,
        clientVersionId: client.meta?.versionId as string,
        membershipVersionId: membership.meta?.versionId as string,
      };
    });
    const accessToken = await initTestAuth({ superAdmin: true });

    const response = await request(app)
      .post('/fhir/R4/$coral-transition-exchange-client')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Content-Type', ContentType.FHIR_JSON)
      .send({
        resourceType: 'Parameters',
        parameter: [
          { name: 'action', valueCode: 'verify' },
          ...Object.entries(versions).map(([name, valueString]) => ({ name, valueString })),
          { name: 'clientSecret', valueString: SECRET },
        ],
      });

    expect(response).toHaveStatus(200);
    expect(response.body).toEqual({
      resourceType: 'Parameters',
      parameter: [{ name: 'status', valueCode: 'verified' }],
    });
    await withTestContext(async () => {
      const state = await readCoralExchangeClientState(getGlobalSystemRepo());
      expect(state).toEqual({ status: 'active', ...versions });
    });
  });

  test('rolls back the policy when a concurrent fixed client already exists', () =>
    withTestContext(async () => {
      const { project } = await createTestProject();
      const systemRepo = getGlobalSystemRepo();
      await systemRepo.createResource<ClientApplication>(
        {
          resourceType: 'ClientApplication',
          id: CORAL_EXCHANGE_CLIENT_ID,
          meta: { project: project.id },
          status: 'off',
          secret: randomUUID(),
        },
        { assignedId: true }
      );

      await expect(stageCoralExchangeClientResources(systemRepo, SECRET)).rejects.toBeDefined();
      await expect(systemRepo.readResource('Project', CORAL_EXCHANGE_PROJECT_ID)).rejects.toBeDefined();
      await expect(systemRepo.readResource('AccessPolicy', CORAL_EXCHANGE_POLICY_ID)).rejects.toBeDefined();
      await expect(systemRepo.readResource('ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID)).rejects.toBeDefined();
      const winner = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      expect(winner.secret).not.toBe(SECRET);
    }));

  test('rejects a pre-existing fixed control Project before creating authority', () =>
    withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();
      await systemRepo.createResource(
        {
          resourceType: 'Project',
          id: CORAL_EXCHANGE_PROJECT_ID,
          name: 'Foreign winner',
          superAdmin: false,
        },
        { assignedId: true }
      );

      await expect(stageCoralExchangeClientResources(systemRepo, SECRET)).rejects.toBeDefined();
      await expect(systemRepo.readResource('ClientApplication', CORAL_EXCHANGE_CLIENT_ID)).rejects.toBeDefined();
    }));

  test('exposes only a super-admin FHIR operation and never echoes the secret', async () => {
    const accessToken = await initTestAuth({ superAdmin: true });

    const response = await request(app)
      .post('/fhir/R4/$coral-stage-exchange-client')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Content-Type', ContentType.FHIR_JSON)
      .send({
        resourceType: 'Parameters',
        parameter: [{ name: 'clientSecret', valueString: SECRET }],
      });

    expect(response).toHaveStatus(201);
    expect(response.body).toEqual({
      resourceType: 'Parameters',
      parameter: [{ name: 'status', valueCode: 'staged' }],
    });
    expect(JSON.stringify(response.body)).not.toContain(SECRET);
  });

  test('exposes a super-admin transition operation with only a sanitized receipt', async () => {
    let versions: Record<string, string> = {};
    await withTestContext(async () => {
      const systemRepo = getGlobalSystemRepo();
      await stageCoralExchangeClientResources(systemRepo, SECRET);
      const project = await systemRepo.readResource<Project>('Project', CORAL_EXCHANGE_PROJECT_ID);
      const policy = await systemRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      const client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      const membership = await systemRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );
      versions = {
        projectVersionId: project.meta?.versionId as string,
        policyVersionId: policy.meta?.versionId as string,
        clientVersionId: client.meta?.versionId as string,
        membershipVersionId: membership.meta?.versionId as string,
      };
    });
    const accessToken = await initTestAuth({ superAdmin: true });

    const response = await request(app)
      .post('/fhir/R4/$coral-transition-exchange-client')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Content-Type', ContentType.FHIR_JSON)
      .send({
        resourceType: 'Parameters',
        parameter: [
          { name: 'action', valueCode: 'activate' },
          ...Object.entries(versions).map(([name, valueString]) => ({ name, valueString })),
          { name: 'clientSecret', valueString: SECRET },
        ],
      });

    expect(response).toHaveStatus(200);
    expect(response.body).toEqual({
      resourceType: 'Parameters',
      parameter: [{ name: 'status', valueCode: 'activated' }],
    });
    expect(JSON.stringify(response.body)).not.toContain(SECRET);
    for (const version of Object.values(versions)) {
      expect(JSON.stringify(response.body)).not.toContain(version);
    }
  });

  test('reads a sanitized staged authority snapshot without exposing the secret or resource IDs', async () => {
    await withTestContext(async () => {
      await stageCoralExchangeClientResources(getGlobalSystemRepo(), SECRET);
    });
    const accessToken = await initTestAuth({ superAdmin: true });

    const response = await request(app)
      .post('/fhir/R4/$coral-exchange-client-state')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Content-Type', ContentType.FHIR_JSON)
      .send({ resourceType: 'Parameters' });

    expect(response).toHaveStatus(200);
    expect(response.body.resourceType).toBe('Parameters');
    expect(response.body.parameter).toEqual([
      { name: 'status', valueCode: 'staged' },
      { name: 'projectVersionId', valueString: expect.any(String) },
      { name: 'policyVersionId', valueString: expect.any(String) },
      { name: 'clientVersionId', valueString: expect.any(String) },
      { name: 'membershipVersionId', valueString: expect.any(String) },
    ]);
    const body = JSON.stringify(response.body);
    expect(body).not.toContain(SECRET);
    for (const id of [
      CORAL_EXCHANGE_PROJECT_ID,
      CORAL_EXCHANGE_POLICY_ID,
      CORAL_EXCHANGE_CLIENT_ID,
      CORAL_EXCHANGE_MEMBERSHIP_ID,
    ]) {
      expect(body).not.toContain(id);
    }
  });
});

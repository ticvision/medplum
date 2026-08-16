// SPDX-FileCopyrightText: Copyright Orangebot, Inc. and Medplum contributors
// SPDX-License-Identifier: Apache-2.0
import { ContentType, createReference } from '@medplum/core';
import type { AccessPolicy, ClientApplication, ProjectMembership } from '@medplum/fhirtypes';
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
  stageCoralExchangeClientResources,
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
      for (const [resourceType, id] of [
        ['ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID],
        ['ClientApplication', CORAL_EXCHANGE_CLIENT_ID],
        ['AccessPolicy', CORAL_EXCHANGE_POLICY_ID],
      ] as const) {
        await systemRepo.deleteResource(resourceType, id).catch(() => undefined);
      }
    });
  });

  test('atomically stages one fixed off client with an inactive deny-all membership', () =>
    withTestContext(async () => {
      const { project } = await createTestProject();
      const systemRepo = getGlobalSystemRepo();

      await stageCoralExchangeClientResources(systemRepo, project.id, SECRET);

      const policy = await systemRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      const client = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      const membership = await systemRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );
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
    }));

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

      await expect(stageCoralExchangeClientResources(systemRepo, project.id, SECRET)).rejects.toBeDefined();
      await expect(systemRepo.readResource('AccessPolicy', CORAL_EXCHANGE_POLICY_ID)).rejects.toBeDefined();
      await expect(systemRepo.readResource('ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID)).rejects.toBeDefined();
      const winner = await systemRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      expect(winner.secret).not.toBe(SECRET);
    }));

  test('rejects a super-admin target before creating any resource', () =>
    withTestContext(async () => {
      const { project } = await createTestProject({ superAdmin: true });
      const systemRepo = getGlobalSystemRepo();

      await expect(stageCoralExchangeClientResources(systemRepo, project.id, SECRET)).rejects.toBeDefined();
      await expect(systemRepo.readResource('ClientApplication', CORAL_EXCHANGE_CLIENT_ID)).rejects.toBeDefined();
    }));

  test('exposes only a super-admin FHIR operation and never echoes the secret', async () => {
    const { project } = await createTestProject();
    const accessToken = await initTestAuth({ superAdmin: true });

    const response = await request(app)
      .post('/fhir/R4/$coral-stage-exchange-client')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Content-Type', ContentType.FHIR_JSON)
      .send({
        resourceType: 'Parameters',
        parameter: [
          { name: 'project', valueReference: createReference(project) },
          { name: 'clientSecret', valueString: SECRET },
        ],
      });

    expect(response).toHaveStatus(201);
    expect(response.body).toEqual({
      resourceType: 'Parameters',
      parameter: [{ name: 'status', valueCode: 'staged' }],
    });
    expect(JSON.stringify(response.body)).not.toContain(SECRET);
  });
});

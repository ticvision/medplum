// SPDX-FileCopyrightText: Copyright Orangebot, Inc. and Medplum contributors
// SPDX-License-Identifier: Apache-2.0
import {
  OperationOutcomeError,
  badRequest,
  createReference,
  created,
  forbidden,
  isGone,
  isNotFound,
  normalizeOperationOutcome,
} from '@medplum/core';
import type { FhirRequest, FhirResponse } from '@medplum/fhir-router';
import type {
  AccessPolicy,
  ClientApplication,
  Project,
  ProjectMembership,
  Reference,
  ResourceType,
} from '@medplum/fhirtypes';
import { getAuthenticatedContext } from '../../context';
import type { SystemRepository } from '../repo';
import { getGlobalSystemRepo } from '../repo';
import { makeOperationDefinition } from './definitions';
import { buildOutputParameters, parseInputParameters } from './utils/parameters';

export const CORAL_EXCHANGE_CLIENT_ID = '9c2f4b6a-7d31-4e58-9a06-8b5f0e2c41d7';
export const CORAL_EXCHANGE_POLICY_ID = '77d9769f-59d2-46de-a5b4-f4ed33b32780';
export const CORAL_EXCHANGE_MEMBERSHIP_ID = '25154d7a-d0b1-4e23-9038-698dd184423d';
export const CORAL_EXCHANGE_POLICY_NAME = 'Coral confidential token exchange deny all';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CLIENT_SECRET = /^[A-Za-z0-9]{64}$/;
const operation = makeOperationDefinition(
  { scope: 'system' },
  {
    name: 'CoralStageExchangeClient',
    code: 'coral-stage-exchange-client',
    parameter: [
      { use: 'in', name: 'project', type: 'Reference', min: 1, max: '1' },
      { use: 'in', name: 'clientSecret', type: 'string', min: 1, max: '1' },
      { use: 'out', name: 'status', type: 'code', min: 1, max: '1' },
    ],
  }
);

interface StageExchangeClientParameters {
  project: Reference;
  clientSecret: string;
}

async function requireCreateOnlyId(repo: SystemRepository, resourceType: ResourceType, id: string): Promise<void> {
  try {
    await repo.readResource(resourceType, id);
  } catch (err) {
    const outcome = normalizeOperationOutcome(err);
    if (isNotFound(outcome) || isGone(outcome)) {
      return;
    }
    throw err;
  }
  throw new OperationOutcomeError(badRequest('Coral exchange authority ID is already in use'));
}

/**
 * Atomically stage the fixed Coral exchange authority in an unusable state.
 *
 * All three creates share one serializable database transaction. A conflicting
 * fixed ID therefore rolls the entire stage back instead of turning a stale
 * GET-404 observation into an overwrite. Activation is deliberately separate.
 * @param systemRepo - Super-admin system repository.
 * @param projectId - Dedicated non-superadmin control Project UUID.
 * @param clientSecret - Exact in-memory AWSCURRENT credential.
 */
export async function stageCoralExchangeClientResources(
  systemRepo: SystemRepository,
  projectId: string,
  clientSecret: string
): Promise<void> {
  if (!UUID.test(projectId) || !CLIENT_SECRET.test(clientSecret)) {
    throw new OperationOutcomeError(badRequest('Invalid Coral exchange authority input'));
  }
  await systemRepo.withTransaction(
    async (txRepo) => {
      const project = await txRepo.readResource<Project>('Project', projectId);
      if (project.superAdmin === true) {
        throw new OperationOutcomeError(badRequest('Invalid Coral exchange authority project'));
      }
      await requireCreateOnlyId(txRepo, 'AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      await requireCreateOnlyId(txRepo, 'ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      await requireCreateOnlyId(txRepo, 'ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID);
      const policy = await txRepo.createResource<AccessPolicy>(
        {
          resourceType: 'AccessPolicy',
          id: CORAL_EXCHANGE_POLICY_ID,
          meta: { project: project.id },
          name: CORAL_EXCHANGE_POLICY_NAME,
          resource: [],
        },
        { assignedId: true }
      );
      const client = await txRepo.createResource<ClientApplication>(
        {
          resourceType: 'ClientApplication',
          id: CORAL_EXCHANGE_CLIENT_ID,
          meta: { project: project.id },
          name: 'Coral Cognito confidential exchange broker',
          status: 'off',
          secret: clientSecret,
        },
        { assignedId: true }
      );
      await txRepo.createResource<ProjectMembership>(
        {
          resourceType: 'ProjectMembership',
          id: CORAL_EXCHANGE_MEMBERSHIP_ID,
          user: createReference(client),
          profile: createReference(client),
          project: createReference(project),
          accessPolicy: createReference(policy),
          active: false,
          admin: false,
        },
        { assignedId: true }
      );
    },
    {
      serializable: true,
      resourceTypes: ['AccessPolicy', 'ClientApplication', 'ProjectMembership', 'Project'],
      source: 'coral.stageExchangeClient',
    }
  );
}

/**
 * Handles the super-admin-only atomic Coral exchange authority stage.
 * @param req - FHIR operation request containing the target Project and secret.
 * @returns A sanitized staged receipt.
 */
export async function coralStageExchangeClientHandler(req: FhirRequest): Promise<FhirResponse> {
  const { project } = getAuthenticatedContext();
  if (project.superAdmin !== true) {
    return [forbidden];
  }
  const input = parseInputParameters<StageExchangeClientParameters>(operation, req);
  const projectId = input.project.reference?.match(/^Project\/([0-9a-f-]+)$/)?.[1];
  if (!projectId) {
    throw new OperationOutcomeError(badRequest('Invalid Coral exchange authority project'));
  }
  await stageCoralExchangeClientResources(getGlobalSystemRepo(), projectId, input.clientSecret);
  return [created, buildOutputParameters(operation, { status: 'staged' })];
}

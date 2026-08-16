// SPDX-FileCopyrightText: Copyright Orangebot, Inc. and Medplum contributors
// SPDX-License-Identifier: Apache-2.0
import {
  OperationOutcomeError,
  Operator,
  allOk,
  badRequest,
  createReference,
  created,
  forbidden,
  isGone,
  isNotFound,
  normalizeOperationOutcome,
  preconditionFailed,
} from '@medplum/core';
import type { FhirRequest, FhirResponse } from '@medplum/fhir-router';
import type { AccessPolicy, ClientApplication, Project, ProjectMembership, ResourceType } from '@medplum/fhirtypes';
import { timingSafeEqual } from 'node:crypto';
import { getAuthenticatedContext } from '../../context';
import { CORAL_EXCHANGE_POLICY_NAME, isSafeConfidentialExchangeAuthority } from '../coralexchangeauthority';
import type { SystemRepository } from '../repo';
import { getGlobalSystemRepo } from '../repo';
import { makeOperationDefinition } from './definitions';
import { buildOutputParameters, parseInputParameters } from './utils/parameters';

export const CORAL_EXCHANGE_CLIENT_ID = '9c2f4b6a-7d31-4e58-9a06-8b5f0e2c41d7';
export const CORAL_EXCHANGE_PROJECT_ID = '5e83f5c7-f0b3-4dc8-a6af-8f0d9b0b0b19';
export const CORAL_EXCHANGE_POLICY_ID = '77d9769f-59d2-46de-a5b4-f4ed33b32780';
export const CORAL_EXCHANGE_MEMBERSHIP_ID = '25154d7a-d0b1-4e23-9038-698dd184423d';
export const CORAL_EXCHANGE_PROJECT_NAME = 'Coral confidential exchange control';
export const CORAL_EXCHANGE_CLIENT_NAME = 'Coral Cognito confidential exchange broker';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CLIENT_SECRET = /^[A-Za-z0-9]{64}$/;
const operation = makeOperationDefinition(
  { scope: 'system' },
  {
    name: 'CoralStageExchangeClient',
    code: 'coral-stage-exchange-client',
    parameter: [
      { use: 'in', name: 'clientSecret', type: 'string', min: 1, max: '1' },
      { use: 'out', name: 'status', type: 'code', min: 1, max: '1' },
    ],
  }
);
const transitionOperation = makeOperationDefinition(
  { scope: 'system' },
  {
    name: 'CoralTransitionExchangeClient',
    code: 'coral-transition-exchange-client',
    parameter: [
      { use: 'in', name: 'action', type: 'code', min: 1, max: '1' },
      { use: 'in', name: 'projectVersionId', type: 'string', min: 1, max: '1' },
      { use: 'in', name: 'policyVersionId', type: 'string', min: 1, max: '1' },
      { use: 'in', name: 'clientVersionId', type: 'string', min: 1, max: '1' },
      { use: 'in', name: 'membershipVersionId', type: 'string', min: 1, max: '1' },
      { use: 'in', name: 'clientSecret', type: 'string', min: 1, max: '1' },
      { use: 'out', name: 'status', type: 'code', min: 1, max: '1' },
    ],
  }
);

interface StageExchangeClientParameters {
  clientSecret: string;
}

export interface TransitionExchangeClientParameters {
  action: 'activate' | 'restage';
  projectVersionId: string;
  policyVersionId: string;
  clientVersionId: string;
  membershipVersionId: string;
  clientSecret: string;
}

function secretsEqual(actual: string | undefined, expected: string): boolean {
  if (!actual || !CLIENT_SECRET.test(actual) || !CLIENT_SECRET.test(expected)) {
    return false;
  }
  return timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

function isExactAuthority(
  project: Project,
  policy: AccessPolicy,
  client: ClientApplication,
  membership: ProjectMembership,
  expectedClientStatus: 'active' | 'off',
  expectedMembershipActive: boolean
): boolean {
  return (
    project.id === CORAL_EXCHANGE_PROJECT_ID &&
    project.name === CORAL_EXCHANGE_PROJECT_NAME &&
    project.superAdmin === false &&
    policy.id === CORAL_EXCHANGE_POLICY_ID &&
    client.id === CORAL_EXCHANGE_CLIENT_ID &&
    client.name === CORAL_EXCHANGE_CLIENT_NAME &&
    membership.id === CORAL_EXCHANGE_MEMBERSHIP_ID &&
    isSafeConfidentialExchangeAuthority(
      project,
      policy,
      client,
      membership,
      expectedClientStatus,
      expectedMembershipActive
    )
  );
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
 * All four creates share one serializable database transaction. A conflicting
 * fixed ID therefore rolls the entire stage back instead of turning a stale
 * GET-404 observation into an overwrite. Activation is deliberately separate.
 * @param systemRepo - Super-admin system repository.
 * @param clientSecret - Exact in-memory AWSCURRENT credential.
 */
export async function stageCoralExchangeClientResources(
  systemRepo: SystemRepository,
  clientSecret: string
): Promise<void> {
  if (!UUID.test(CORAL_EXCHANGE_PROJECT_ID) || !CLIENT_SECRET.test(clientSecret)) {
    throw new OperationOutcomeError(badRequest('Invalid Coral exchange authority input'));
  }
  await systemRepo.withTransaction(
    async (txRepo) => {
      await requireCreateOnlyId(txRepo, 'Project', CORAL_EXCHANGE_PROJECT_ID);
      await requireCreateOnlyId(txRepo, 'AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      await requireCreateOnlyId(txRepo, 'ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      await requireCreateOnlyId(txRepo, 'ProjectMembership', CORAL_EXCHANGE_MEMBERSHIP_ID);
      const project = await txRepo.createResource<Project>(
        {
          resourceType: 'Project',
          id: CORAL_EXCHANGE_PROJECT_ID,
          name: CORAL_EXCHANGE_PROJECT_NAME,
          strictMode: true,
          superAdmin: false,
        },
        { assignedId: true }
      );
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
          name: CORAL_EXCHANGE_CLIENT_NAME,
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
 * Atomically transition the exact fixed Coral exchange authority.
 * @param systemRepo - Super-admin system repository.
 * @param input - Expected resource versions, action, and in-memory credential.
 */
export async function transitionCoralExchangeClientResources(
  systemRepo: SystemRepository,
  input: TransitionExchangeClientParameters
): Promise<void> {
  if (
    !UUID.test(input.projectVersionId) ||
    !UUID.test(input.policyVersionId) ||
    !UUID.test(input.clientVersionId) ||
    !UUID.test(input.membershipVersionId) ||
    !CLIENT_SECRET.test(input.clientSecret) ||
    !['activate', 'restage'].includes(input.action)
  ) {
    throw new OperationOutcomeError(badRequest('Invalid Coral exchange authority transition'));
  }
  await systemRepo.withTransaction(
    async (txRepo) => {
      const project = await txRepo.readResource<Project>('Project', CORAL_EXCHANGE_PROJECT_ID);
      const policy = await txRepo.readResource<AccessPolicy>('AccessPolicy', CORAL_EXCHANGE_POLICY_ID);
      const client = await txRepo.readResource<ClientApplication>('ClientApplication', CORAL_EXCHANGE_CLIENT_ID);
      const membership = await txRepo.readResource<ProjectMembership>(
        'ProjectMembership',
        CORAL_EXCHANGE_MEMBERSHIP_ID
      );
      const memberships = await txRepo.searchResources<ProjectMembership>({
        resourceType: 'ProjectMembership',
        count: 2,
        filters: [
          {
            code: 'user',
            operator: Operator.EQUALS,
            value: `ClientApplication/${CORAL_EXCHANGE_CLIENT_ID}`,
          },
        ],
      });
      if (
        project.meta?.versionId !== input.projectVersionId ||
        policy.meta?.versionId !== input.policyVersionId ||
        client.meta?.versionId !== input.clientVersionId ||
        membership.meta?.versionId !== input.membershipVersionId
      ) {
        throw new OperationOutcomeError(preconditionFailed);
      }
      const expectedState =
        input.action === 'activate'
          ? {
              clientStatus: 'off' as const,
              membershipActive: false,
              nextClientStatus: 'active' as const,
              nextActive: true,
            }
          : input.action === 'restage'
            ? {
                clientStatus: 'active' as const,
                membershipActive: true,
                nextClientStatus: 'off' as const,
                nextActive: false,
              }
            : undefined;
      if (
        !expectedState ||
        memberships.length !== 1 ||
        memberships[0].id !== CORAL_EXCHANGE_MEMBERSHIP_ID ||
        !isExactAuthority(
          project,
          policy,
          client,
          membership,
          expectedState.clientStatus,
          expectedState.membershipActive
        ) ||
        !secretsEqual(client.secret, input.clientSecret)
      ) {
        throw new OperationOutcomeError(badRequest('Invalid Coral exchange authority transition'));
      }
      await txRepo.updateResource<ClientApplication>(
        { ...client, status: expectedState.nextClientStatus },
        { ifMatch: input.clientVersionId }
      );
      await txRepo.updateResource<ProjectMembership>(
        { ...membership, active: expectedState.nextActive },
        { ifMatch: input.membershipVersionId }
      );
    },
    {
      serializable: true,
      resourceTypes: ['AccessPolicy', 'ClientApplication', 'ProjectMembership', 'Project'],
      source: 'coral.transitionExchangeClient',
    }
  );
}

/**
 * Handles the super-admin-only atomic Coral exchange authority stage.
 * @param req - FHIR operation request containing only the staged secret.
 * @returns A sanitized staged receipt.
 */
export async function coralStageExchangeClientHandler(req: FhirRequest): Promise<FhirResponse> {
  const { project } = getAuthenticatedContext();
  if (project.superAdmin !== true) {
    return [forbidden];
  }
  const input = parseInputParameters<StageExchangeClientParameters>(operation, req);
  await stageCoralExchangeClientResources(getGlobalSystemRepo(), input.clientSecret);
  return [created, buildOutputParameters(operation, { status: 'staged' })];
}

/**
 * Handles the super-admin-only conditional Coral exchange authority transition.
 * @param req - FHIR operation request containing the action, expected versions, and secret.
 * @returns A sanitized transition receipt.
 */
export async function coralTransitionExchangeClientHandler(req: FhirRequest): Promise<FhirResponse> {
  const { project } = getAuthenticatedContext();
  if (project.superAdmin !== true) {
    return [forbidden];
  }
  const input = parseInputParameters<TransitionExchangeClientParameters>(transitionOperation, req);
  await transitionCoralExchangeClientResources(getGlobalSystemRepo(), input);
  return [
    allOk,
    buildOutputParameters(transitionOperation, {
      status: input.action === 'activate' ? 'activated' : 'restaged',
    }),
  ];
}

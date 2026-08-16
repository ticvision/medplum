// SPDX-FileCopyrightText: Copyright Orangebot, Inc. and Medplum contributors
// SPDX-License-Identifier: Apache-2.0
import { resolveId } from '@medplum/core';
import type { AccessPolicy, ClientApplication, Project, ProjectMembership } from '@medplum/fhirtypes';

export const CORAL_EXCHANGE_POLICY_NAME = 'Coral confidential token exchange deny all';

/**
 * Returns true only for the inert authority graph used by confidential
 * server-side token exchange clients.
 *
 * The graph is deliberately stricter than ordinary Medplum applications: the
 * client has no browser or identity-provider authority, the project cannot
 * inherit access, and the membership points at one explicit empty policy.
 */
export function isSafeConfidentialExchangeAuthority(
  project: Project,
  policy: AccessPolicy,
  client: ClientApplication,
  membership: ProjectMembership,
  expectedClientStatus: 'active' | 'off',
  expectedMembershipActive: boolean
): boolean {
  const clientReference = client.id ? `ClientApplication/${client.id}` : undefined;
  return (
    !!project.id &&
    !!policy.id &&
    !!clientReference &&
    project.strictMode === true &&
    project.superAdmin !== true &&
    project.defaultPatientAccessPolicy === undefined &&
    (project.defaultAccessPolicies?.length ?? 0) === 0 &&
    policy.meta?.project === project.id &&
    policy.name === CORAL_EXCHANGE_POLICY_NAME &&
    (policy.resource?.length ?? 0) === 0 &&
    (policy.basedOn?.length ?? 0) === 0 &&
    policy.compartment === undefined &&
    (policy.ipAccessRule?.length ?? 0) === 0 &&
    client.meta?.project === project.id &&
    client.status === expectedClientStatus &&
    client.retiringSecret === undefined &&
    client.identityProvider === undefined &&
    client.jwksUri === undefined &&
    (client.redirectUris?.length ?? 0) === 0 &&
    client.redirectUri === undefined &&
    (client.allowedOrigin?.length ?? 0) === 0 &&
    client.certificateTrustStore === undefined &&
    membership.active === expectedMembershipActive &&
    membership.admin === false &&
    membership.access === undefined &&
    membership.user?.reference === clientReference &&
    membership.profile?.reference === clientReference &&
    resolveId(membership.project) === project.id &&
    resolveId(membership.accessPolicy) === policy.id
  );
}

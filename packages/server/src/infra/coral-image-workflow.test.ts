// SPDX-FileCopyrightText: Copyright Orangebot, Inc. and Medplum contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';

const workflowPath = fileURLToPath(new URL('../../../../.github/workflows/coral-medplum-image.yml', import.meta.url));
const buildScriptPath = fileURLToPath(new URL('../../../../scripts/build-docker-server.sh', import.meta.url));

describe('Coral Medplum immutable image workflow', () => {
  test('is manual, source-bound, scan-gated, and never deploys', () => {
    const workflow = readFileSync(workflowPath, 'utf8');

    expect(workflow).toContain('name: Coral Medplum immutable image');
    expect(workflow).toMatch(/on:\n {2}workflow_dispatch:\s*\n/);
    expect(workflow).not.toMatch(/\n {2}(push|pull_request|schedule):/);
    expect(workflow).toContain('environment: medplum-dev-image');
    expect(workflow).toContain('permissions:\n      contents: read\n      id-token: write');
    expect(workflow).toContain('refs/heads/feat/coral-medplum-confidential-exchange-0815');

    const install = workflow.indexOf('run: npm ci');
    const testServer = workflow.indexOf('src/oauth/token.test.ts');
    const audit = workflow.indexOf('npm audit --audit-level=high --omit=dev --workspace=@medplum/server');
    const build = workflow.indexOf('run: npm run build');
    const credentials = workflow.indexOf('aws-actions/configure-aws-credentials@');
    const existingImage = workflow.indexOf('id: existing_image');
    const push = workflow.indexOf('./scripts/build-docker-server.sh');
    const scan = workflow.indexOf('aws ecr wait image-scan-complete');
    expect(install).toBeGreaterThan(-1);
    expect(testServer).toBeGreaterThan(install);
    expect(audit).toBeGreaterThan(testServer);
    expect(build).toBeGreaterThan(audit);
    expect(credentials).toBeGreaterThan(build);
    expect(existingImage).toBeGreaterThan(credentials);
    expect(push).toBeGreaterThan(credentials);
    expect(scan).toBeGreaterThan(push);
    expect(workflow).toContain('npm exec --workspace=@medplum/server -- vitest run');

    expect(workflow).toContain(
      'role-to-assume: arn:aws:iam::689186650710:role/github-actions-coral-medplum-image-build'
    );
    expect(workflow).toContain('aws sts get-caller-identity');
    expect(workflow).toContain('689186650710.dkr.ecr.us-east-2.amazonaws.com/coralehr/medplum-dev-server');
    expect(workflow).toContain('SERVER_DOCKER_PLATFORMS: linux/amd64');
    expect(workflow).toContain('DHI_USERNAME');
    expect(workflow).toContain('DHI_TOKEN');
    expect(workflow).toContain('imageTagMutability');
    expect(workflow).toContain('imageScanningConfiguration.scanOnPush');
    expect(workflow).toContain('aws ecr get-registry-scanning-configuration');
    expect(workflow).toContain('scanFrequency == "SCAN_ON_PUSH"');
    expect(workflow).toContain('docker buildx imagetools inspect "$SERVER_DOCKER_IMAGE" --raw');
    expect(workflow).toContain('RUNTIME_MANIFEST_DIGEST');
    expect(workflow).toContain('.platform.architecture == "amd64"');
    expect(workflow).toContain('imageDigest=$RUNTIME_MANIFEST_DIGEST');
    expect(workflow).toContain('vnd.docker.reference.type');
    expect(workflow).toContain('https://slsa.dev/provenance/');
    expect(workflow).toContain('https://spdx.dev/Document');
    expect(workflow).toContain('findingSeverityCounts.CRITICAL');
    expect(workflow).toContain('findingSeverityCounts.HIGH');
    expect(workflow).toContain(['SERVER_DOCKER_IMAGE=$', '{SERVER_DOCKER_IMAGE}'].join(''));
    expect(workflow).toContain(['RUNTIME_MANIFEST_DIGEST=$', '{RUNTIME_MANIFEST_DIGEST}'].join(''));
    expect(workflow).toContain('ATTESTATIONS=SLSA_PROVENANCE:verified,SPDX_SBOM:verified');
    expect(workflow).toContain("if: steps.existing_image.outputs.exists != 'true'");
    expect(workflow).toContain('SERVER_DOCKER_IMAGE_DIGEST=$EXISTING_DIGEST');
    expect(workflow).toContain('existing immutable commit image; resuming verification');

    expect(workflow).not.toContain('--latest');
    expect(workflow).not.toContain('--release');
    expect(workflow).not.toMatch(/\b(ecs|cloudformation|ssm)\s+(deploy|update|put|delete|execute)/);

    const buildScript = readFileSync(buildScriptPath, 'utf8');
    expect(buildScript).toContain('SERVER_DOCKER_PLATFORMS:-linux/amd64,linux/arm64');
    expect(buildScript).toContain('PLATFORMS=(--platform "$DOCKER_PLATFORMS")');
  });
});

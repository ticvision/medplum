# Coral security delta for Medplum 5.1.29

This branch is a pinned Coral fork of Medplum `v5.1.29`. It records the two
server decisions required by Coral's first Patient Appointment compatibility
slice. These are product security contracts, not opportunistic upstream edits.

## Confidential external token exchange

- Every RFC 8693 exchange authenticates one active `ClientApplication` before
  Medplum calls the external userinfo endpoint.
- A server-level `externalAuthProviders` entry selects an identity provider; it
  never waives OAuth client authentication.
- `client_secret_post`, `client_secret_basic`, mTLS, and an already-verified
  `private_key_jwt` reuse Medplum's existing credential parser. Missing, unknown,
  inactive, or invalid clients fail before userinfo.
- The deprecated JSON `/auth/exchange` route also requires a client secret. A
  valid external bearer plus membership ID is never sufficient by itself.
- Successful tokens retain the authenticated `client_id` for attribution and
  client-specific lifetime policy.

The Coral broker reads its credential from one CMK-encrypted AWS Secrets Manager
secret. A separate bounded operator must reconcile the matching
`ClientApplication`; secret material must never enter argv, logs, Git, test
fixtures, CloudFormation outputs, or public failure responses.

## PHI-safe operational logging

- Request logs record only the normalized mounted route path, never
  `req.originalUrl`; FHIR query parameters and OAuth callback values are excluded.
- Authenticated context logs retain only Project scope, profile resource type,
  and a boolean on-behalf-of marker. Patient, Practitioner, Bot, and client IDs
  are excluded.
- Failed-login logs use boolean presence flags and the authentication method;
  email, external subject, Project, membership, password, and challenge values
  are excluded.

Synthetic tests must include marker values and prove those markers do not reach
captured logs. The fork is not activation-ready until its image is built,
deployed in the isolated Medplum stack, and the live ECS log scan passes.

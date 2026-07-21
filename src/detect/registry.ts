// Central registry of detection checks. Register new checks here (or via
// `registerCheck`) and they are automatically applied to every probe.

import type { Check, Finding, ProbeResult, CheckContext } from '../types.js';
import { securityHeadersCheck } from './checks/security-headers.js';
import { exposedFilesCheck } from './checks/exposed-files.js';
import { corsCheck } from './checks/cors.js';
import { cookiesCheck } from './checks/cookies.js';
import { versionCveCheck } from './checks/version-cve.js';
import { apiSchemaExposureCheck } from './checks/api-schema-exposure.js';
import { graphqlIntrospectionCheck } from './checks/graphql-introspection.js';
import { authAccessCheck } from './checks/auth-access.js';
import { weakJwtCheck } from './checks/weak-jwt.js';
import { rateLimitCheck } from './checks/rate-limit.js';
import { secretsExposureCheck } from '../recon/secrets.js';

const REGISTRY: Check[] = [
  securityHeadersCheck,
  exposedFilesCheck,
  corsCheck,
  cookiesCheck,
  versionCveCheck,
  apiSchemaExposureCheck,
  graphqlIntrospectionCheck,
  authAccessCheck,
  weakJwtCheck,
  secretsExposureCheck,
  rateLimitCheck,
];

export function registerCheck(check: Check): void {
  if (REGISTRY.some((c) => c.id === check.id)) {
    throw new Error(`Duplicate check id: ${check.id}`);
  }
  REGISTRY.push(check);
}

export function listChecks(): Check[] {
  return [...REGISTRY];
}

/** Run all registered checks against one probe. */
export function runChecks(probe: ProbeResult, ctx: CheckContext): Finding[] {
  const findings: Finding[] = [];
  for (const check of REGISTRY) {
    try {
      findings.push(...check.run(probe, ctx));
    } catch (e) {
      // A misbehaving check must never abort the scan.
      console.error(`check ${check.id} threw:`, e);
    }
  }
  return findings;
}

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
import { weakCspCheck } from './checks/weak-csp.js';
import { sourcemapCheck } from './checks/sourcemap.js';
import { oauthMisconfigCheck } from './checks/oauth.js';
import { authAccessCheck } from './checks/auth-access.js';
import { cacheDeceptionCheck } from './checks/cache-deception.js';
import { subdomainTakeoverCheck } from './checks/subdomain-takeover.js';
import { cloudBucketCheck } from './checks/cloud-bucket.js';
import { debugDisclosureCheck } from './checks/debug-disclosure.js';
import { directoryListingCheck } from './checks/directory-listing.js';
import { emailSpoofingCheck } from './checks/email-spoofing.js';
import { openRedirectCheck } from './checks/open-redirect.js';
import { hostHeaderCheck } from './checks/host-header.js';
import { ssrfCandidateCheck } from './checks/ssrf-candidate.js';
import { jwtExposureCheck } from './checks/jwt.js';
import { xssReflectionCheck } from './checks/xss-reflection.js';
import { authDifferentialCheck } from './checks/auth-differential.js';
import { insecureSubresourceCheck } from './checks/insecure-subresource.js';
import { scanSecrets } from '../recon/secrets.js';

const REGISTRY: Check[] = [
  securityHeadersCheck,
  exposedFilesCheck,
  corsCheck,
  cookiesCheck,
  versionCveCheck,
  apiSchemaExposureCheck,
  graphqlIntrospectionCheck,
  weakCspCheck,
  sourcemapCheck,
  oauthMisconfigCheck,
  authAccessCheck,
  authDifferentialCheck,
  cacheDeceptionCheck,
  subdomainTakeoverCheck,
  cloudBucketCheck,
  debugDisclosureCheck,
  directoryListingCheck,
  emailSpoofingCheck,
  openRedirectCheck,
  hostHeaderCheck,
  ssrfCandidateCheck,
  jwtExposureCheck,
  xssReflectionCheck,
  insecureSubresourceCheck,
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

/** Run all registered checks (plus the secret scanner) against one probe. */
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
  findings.push(...scanSecrets(probe));
  return findings;
}

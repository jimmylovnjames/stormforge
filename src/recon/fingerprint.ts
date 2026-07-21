// Passive technology fingerprinting from response headers and body markers.
// Read-only: infers stack/versions to feed the version-CVE check and to hint
// the scanner toward GraphQL/OpenAPI follow-up probes. No extra I/O here.

import type { ProbeResult } from '../types.js';
import { parseBodySignals } from './body-parse.js';

export interface TechMatch {
  product: string;
  version?: string;
  source: string; // where we saw it
}

interface HeaderRule {
  header: string;
  product: string;
  /** Capture group 1 = version, if present. */
  versionRegex?: RegExp;
}

const HEADER_RULES: HeaderRule[] = [
  { header: 'server', product: 'nginx', versionRegex: /nginx\/([\d.]+)/i },
  { header: 'server', product: 'Apache', versionRegex: /Apache\/([\d.]+)/i },
  { header: 'server', product: 'Microsoft-IIS', versionRegex: /IIS\/([\d.]+)/i },
  { header: 'x-powered-by', product: 'PHP', versionRegex: /PHP\/([\d.]+)/i },
  { header: 'x-powered-by', product: 'Express' },
  { header: 'x-powered-by', product: 'ASP.NET' },
  { header: 'x-generator', product: 'Drupal', versionRegex: /Drupal ([\d.]+)/i },
  { header: 'x-drupal-cache', product: 'Drupal' },
  // API / GraphQL stacks
  { header: 'x-graphql-yoga-csrf', product: 'GraphQL Yoga' },
  { header: 'x-apollo-operation-name', product: 'Apollo GraphQL' },
  { header: 'x-hasura-role', product: 'Hasura' },
  { header: 'x-hasura-query-id', product: 'Hasura' },
  // Rate limiting / edge controls
  { header: 'ratelimit-limit', product: 'Rate Limiting' },
  { header: 'x-ratelimit-limit', product: 'Rate Limiting' },
  { header: 'x-rate-limit-limit', product: 'Rate Limiting' },
  { header: 'cf-ray', product: 'Cloudflare' },
];

const BODY_RULES: { product: string; regex: RegExp }[] = [
  { product: 'WordPress', regex: /<meta name="generator" content="WordPress ([\d.]+)"/i },
  { product: 'Drupal', regex: /Drupal ([\d.]+)/i },
  { product: 'jQuery', regex: /jquery[-.]?([\d.]+)(?:\.min)?\.js/i },
  { product: 'GraphiQL', regex: /\bGraphiQL\b|graphiql\.min\.js/i },
  { product: 'GraphQL Playground', regex: /GraphQL Playground|graphql-playground/i },
  { product: 'Apollo Server', regex: /ApolloServer|apollo-server|apollo-client/i },
  { product: 'Hasura', regex: /hasura|x-hasura/i },
  { product: 'Swagger UI', regex: /SwaggerUIBundle|swagger-ui(-dist)?/i },
  { product: 'ReDoc', regex: /<redoc[\s>]|redoc\.standalone/i },
  { product: 'OpenAPI', regex: /"openapi"\s*:\s*"3\./i },
  { product: 'Swagger', regex: /"swagger"\s*:\s*"2\.0"/i },
  // Auth / identity surfaces
  { product: 'JWT', regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\./ },
  { product: 'OAuth', regex: /"access_token"\s*:|"token_type"\s*:\s*"bearer"/i },
];

export function fingerprint(probe: ProbeResult): TechMatch[] {
  const out: TechMatch[] = [];
  const seen = new Set<string>();

  const add = (m: TechMatch) => {
    const key = `${m.product}@${m.version ?? '?'}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(m);
    }
  };

  for (const rule of HEADER_RULES) {
    const value = probe.headers[rule.header];
    if (value === undefined) continue;
    if (rule.versionRegex) {
      if (!value) continue;
      const m = value.match(rule.versionRegex);
      if (m) add({ product: rule.product, version: m[1], source: `header:${rule.header}` });
      else if (value.toLowerCase().includes(rule.product.toLowerCase()))
        add({ product: rule.product, source: `header:${rule.header}` });
    } else {
      // Header presence alone is enough for these API markers (value may be a token).
      add({ product: rule.product, source: `header:${rule.header}` });
    }
  }

  if (probe.body) {
    for (const rule of BODY_RULES) {
      const m = probe.body.match(rule.regex);
      if (m) add({ product: rule.product, version: m[1], source: 'body' });
    }

    const signals = probe.signals ?? parseBodySignals(probe.body, probe.headers, probe.status);
    if (signals.graphqlIntrospection) add({ product: 'GraphQL', source: 'body:introspection' });
    if (signals.openApiVersion?.startsWith('openapi')) {
      add({ product: 'OpenAPI', version: signals.openApiVersion.replace('openapi-', ''), source: 'body:spec' });
    }
    if (signals.openApiVersion?.startsWith('swagger')) {
      add({ product: 'Swagger', version: signals.openApiVersion.replace('swagger-', ''), source: 'body:spec' });
    }
  }

  return out;
}

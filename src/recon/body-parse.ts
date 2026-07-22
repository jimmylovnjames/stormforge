// Structured analysis of HTTP response bodies (2xx probes).
// Pure / sync — used by the scanner and detection checks. No I/O.

import type { BodySignals } from '../types.js';

// No spaces — keeps GET query-string encoding portable across URLSearchParams.
const INTROSPECTION_QUERY =
  '{__schema{queryType{name}mutationType{name}types{name,kind}}}';

/** Minimal read-only GraphQL introspection query (GET-safe). */
export function graphqlIntrospectionQuery(): string {
  return INTROSPECTION_QUERY;
}

/**
 * Append a safe GET introspection query to a GraphQL endpoint URL.
 * Does not mutate the original; returns a new absolute URL string.
 */
export function buildGraphqlIntrospectionUrl(endpointUrl: string): string {
  const u = new URL(endpointUrl);
  if (!u.searchParams.has('query')) {
    u.searchParams.set('query', INTROSPECTION_QUERY);
  }
  return u.toString();
}

export function parseBodySignals(
  body: string,
  headers: Record<string, string> = {},
  status = 200,
): BodySignals {
  const empty: BodySignals = {
    kind: 'empty',
    openApiPathCount: 0,
    graphqlIntrospection: false,
    graphqlExplorer: false,
    swaggerUi: false,
    graphqlEndpointHint: false,
    preview: '',
  };
  if (!body) return empty;

  const ct = (headers['content-type'] ?? '').toLowerCase();
  const kind = classifyKind(body, ct);
  const preview = body.slice(0, 240).replace(/\s+/g, ' ');

  const openapi = detectOpenApiSignals(body);
  const graphqlIntrospection = hasGraphqlIntrospection(body);
  const graphqlExplorer = hasGraphqlExplorer(body);
  const swaggerUi = hasSwaggerUi(body);
  const graphqlEndpointHint =
    graphqlIntrospection ||
    graphqlExplorer ||
    hasGraphqlEndpointHint(body, ct, headers, status);

  return {
    kind,
    openApiPathCount: openapi.pathCount,
    openApiVersion: openapi.version,
    graphqlIntrospection,
    graphqlExplorer,
    swaggerUi,
    graphqlEndpointHint,
    preview,
  };
}

function classifyKind(body: string, ct: string): BodySignals['kind'] {
  if (ct.includes('application/json') || /^\s*[{\[]/.test(body)) return 'json';
  if (ct.includes('text/html') || /^\s*</.test(body)) return 'html';
  if (ct.includes('yaml') || /^openapi:\s*/m.test(body) || /^swagger:\s*/m.test(body)) return 'yaml';
  return 'text';
}

export function hasGraphqlIntrospection(body: string): boolean {
  if (!body.includes('__schema')) return false;
  const hasQueryType = /"queryType"\s*:/.test(body);
  const hasMutationType = /"mutationType"\s*:/.test(body);
  const hasTypes = /"types"\s*:\s*\[/.test(body);
  return (hasQueryType || hasMutationType) && (hasTypes || hasQueryType);
}

function hasGraphqlExplorer(body: string): boolean {
  return (
    /GraphQL Playground/i.test(body) ||
    /graphql-playground/i.test(body) ||
    /\bGraphiQL\b/.test(body) ||
    /graphiql\.min\.js/i.test(body) ||
    /cdn\.jsdelivr\.net\/npm\/graphiql/i.test(body)
  );
}

function hasSwaggerUi(body: string): boolean {
  return (
    /SwaggerUIBundle/.test(body) ||
    /swagger-ui(-dist|-bundle)?(\.min)?\.js/i.test(body) ||
    /id=["']swagger-ui["']/i.test(body) ||
    /<redoc[\s>]/i.test(body) ||
    /redoc\.standalone\.js/i.test(body)
  );
}

function hasGraphqlEndpointHint(
  body: string,
  ct: string,
  headers: Record<string, string>,
  status: number,
): boolean {
  if (ct.includes('application/graphql')) return true;
  if (headers['x-graphql-yoga-csrf'] !== undefined) return true;
  if (headers['x-apollo-operation-name'] !== undefined) return true;
  if (
    status >= 200 &&
    status < 500 &&
    /"errors"\s*:\s*\[/.test(body) &&
    (/Must provide query string/i.test(body) ||
      /GET query missing/i.test(body) ||
      /query parameter is required/i.test(body) ||
      /GraphQL/i.test(body))
  ) {
    return true;
  }
  return false;
}

function detectOpenApiSignals(body: string): { pathCount: number; version?: string } {
  const trimmed = body.trim();
  let version: string | undefined;

  const openapi3 = /"openapi"\s*:\s*"(3\.\d+(?:\.\d+)?)"/.exec(trimmed);
  const swagger2 = /"swagger"\s*:\s*"(2\.0)"/.exec(trimmed);
  const yamlOpenapi = /^openapi:\s*['"]?(3\.\d+(?:\.\d+)?)['"]?/m.exec(trimmed);
  const yamlSwagger = /^swagger:\s*['"]?(2\.0)['"]?/m.exec(trimmed);

  if (openapi3) version = `openapi-${openapi3[1]}`;
  else if (swagger2) version = `swagger-${swagger2[1]}`;
  else if (yamlOpenapi) version = `openapi-${yamlOpenapi[1]}`;
  else if (yamlSwagger) version = `swagger-${yamlSwagger[1]}`;
  else return { pathCount: 0 };

  const hasInfo =
    /"info"\s*:\s*\{/.test(trimmed) || /^info:\s*$/m.test(trimmed) || /^info:\s*\{/m.test(trimmed);
  let pathCount = 0;

  if (/"paths"\s*:\s*\{/.test(trimmed) || /^paths:\s*$/m.test(trimmed)) {
    pathCount = (trimmed.match(/"\/[A-Za-z0-9_{}\-/.]+"\s*:/g) ?? []).length;
  }

  if (!hasInfo && pathCount === 0) return { pathCount: 0 };
  return { pathCount, version };
}

/** Pathname looks like a GraphQL or explorer route. */
export function pathLooksLikeGraphql(url: string): boolean {
  try {
    const p = new URL(url).pathname.toLowerCase();
    return (
      p.includes('graphql') ||
      p.includes('graphiql') ||
      p.endsWith('/gql') ||
      p.includes('/playground')
    );
  } catch {
    return /graphql/i.test(url);
  }
}

export function shouldFollowUpGraphqlIntrospection(
  url: string,
  status: number,
  signals: BodySignals,
): boolean {
  if (signals.graphqlIntrospection) return false;
  if (status < 200 || status >= 500) return false;
  return pathLooksLikeGraphql(url) || signals.graphqlEndpointHint || signals.graphqlExplorer;
}

// GraphQL introspection → IDOR-shaped field fan-out.
// Pure / sync. Builds GET-safe introspection field probes (never mutates).

import type { ProbeResult, Scope } from '../types.js';
import { evaluateScope } from '../scope/scope-guard.js';
import { parseBodySignals } from './body-parse.js';

export interface GraphqlIdorField {
  /** Field name on Query / Mutation (e.g. `user`). */
  field: string;
  /** Argument name that looks like an object id (e.g. `id`, `userId`). */
  arg: string;
  /** Parent root type. */
  root: 'Query' | 'Mutation';
}

const ID_ARG = /^(?:id|uuid|guid|userId|user_id|accountId|account_id|orderId|order_id|customerId|orgId|tenantId)$/i;
const ID_FIELD = /^(?:user|users|account|accounts|profile|profiles|order|orders|customer|customers|org|organization|tenant)(?:ById)?$/i;
const SAMPLE_IDS = ['1', '2', 'me'];

/**
 * Extract Query/Mutation fields with ID-like args from an introspection JSON body.
 * Works against both the minimal StormForge query and richer schemas.
 */
export function extractGraphqlIdorFields(body: string): GraphqlIdorField[] {
  if (!body || !body.includes('__schema')) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    // Sometimes the introspection is nested under data
    const m = /"data"\s*:\s*(\{[\s\S]*"__schema"[\s\S]*\})\s*[,}]/.exec(body);
    if (!m?.[1]) return extractGraphqlIdorFieldsLoose(body);
    try {
      parsed = { data: JSON.parse(m[1]) };
    } catch {
      return extractGraphqlIdorFieldsLoose(body);
    }
  }

  const schema =
    (parsed as { data?: { __schema?: SchemaNode } })?.data?.__schema ??
    (parsed as { __schema?: SchemaNode })?.__schema;
  if (!schema?.types || !Array.isArray(schema.types)) {
    return extractGraphqlIdorFieldsLoose(body);
  }

  const queryName = schema.queryType?.name ?? 'Query';
  const mutationName = schema.mutationType?.name ?? 'Mutation';
  const out: GraphqlIdorField[] = [];
  const seen = new Set<string>();

  for (const t of schema.types) {
    if (!t?.name || !Array.isArray(t.fields)) continue;
    const root: 'Query' | 'Mutation' | null =
      t.name === queryName ? 'Query' : t.name === mutationName ? 'Mutation' : null;
    if (!root) continue;
    // Prefer Query for GET-safe fan-out; skip Mutation writes.
    if (root === 'Mutation') continue;
    for (const f of t.fields) {
      if (!f?.name || !Array.isArray(f.args)) continue;
      const idArg = f.args.find((a) => a?.name && ID_ARG.test(a.name));
      if (!idArg && !ID_FIELD.test(f.name)) continue;
      const arg = idArg?.name ?? f.args.find((a) => a?.name && /id/i.test(a.name))?.name;
      if (!arg) continue;
      const key = `${root}.${f.name}.${arg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ field: f.name, arg, root });
    }
  }
  return out;
}

/** Regex fallback when JSON parse fails or schema is truncated. */
function extractGraphqlIdorFieldsLoose(body: string): GraphqlIdorField[] {
  const out: GraphqlIdorField[] = [];
  const seen = new Set<string>();
  // "name":"user",..."args":[{"name":"id"
  const re =
    /"name"\s*:\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*,\s*(?:"description"\s*:\s*"[^"]*"\s*,\s*)?"args"\s*:\s*\[\s*\{\s*"name"\s*:\s*"([A-Za-z_][A-Za-z0-9_]*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const field = m[1]!;
    const arg = m[2]!;
    if (!ID_ARG.test(arg) && !ID_FIELD.test(field)) continue;
    if (!ID_ARG.test(arg) && !/id/i.test(arg)) continue;
    const key = `Query.${field}.${arg}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ field, arg, root: 'Query' });
  }
  return out;
}

interface SchemaNode {
  queryType?: { name?: string };
  mutationType?: { name?: string } | null;
  types?: Array<{
    name?: string;
    fields?: Array<{ name?: string; args?: Array<{ name?: string }> }> | null;
  }>;
}

/** Build GET-safe GraphQL query strings for IDOR-ish fields. */
export function materializeGraphqlQueries(fields: GraphqlIdorField[], cap = 12): string[] {
  const out: string[] = [];
  for (const f of fields) {
    for (const sample of SAMPLE_IDS) {
      if (out.length >= cap) return out;
      // Prefer string args for "me"; numeric-looking otherwise without quotes when pure digits.
      const lit = sample === 'me' || !/^\d+$/.test(sample) ? `"${sample}"` : sample;
      out.push(`{${f.field}(${f.arg}:${lit}){__typename}}`);
    }
  }
  return out;
}

/** Attach queries as `?query=` on the GraphQL endpoint origin path. */
export function materializeGraphqlUrls(endpointUrl: string, fields: GraphqlIdorField[], cap = 12): string[] {
  let base: URL;
  try {
    base = new URL(endpointUrl.includes('://') ? endpointUrl : `https://${endpointUrl}`);
  } catch {
    return [];
  }
  // Drop previous introspection query params.
  base.search = '';
  const out: string[] = [];
  const seen = new Set<string>();
  for (const q of materializeGraphqlQueries(fields, cap)) {
    const u = new URL(base.toString());
    u.searchParams.set('query', q);
    const href = u.toString();
    if (seen.has(href)) continue;
    seen.add(href);
    out.push(href);
  }
  return out;
}

/**
 * From probes that already returned GraphQL introspection, build in-scope
 * GET follow-up URLs targeting IDOR-shaped Query fields.
 */
export function buildGraphqlIdorFollowUps(probes: ProbeResult[], scope: Scope, cap = 16): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const p of probes) {
    if (out.length >= cap) break;
    if (p.error || !p.body) continue;
    const signals = p.signals ?? parseBodySignals(p.body, p.headers, p.status);
    if (!signals.graphqlIntrospection) continue;
    const fields = extractGraphqlIdorFields(p.body);
    if (!fields.length) continue;
    let endpoint = p.finalUrl ?? p.url;
    try {
      const u = new URL(endpoint);
      u.search = '';
      endpoint = u.toString();
    } catch {
      /* keep */
    }
    for (const url of materializeGraphqlUrls(endpoint, fields, cap - out.length)) {
      if (seen.has(url)) continue;
      if (!evaluateScope(url, scope).allowed) continue;
      if (probes.some((x) => x.url === url)) continue;
      seen.add(url);
      out.push(url);
      if (out.length >= cap) break;
    }
  }
  return out;
}

export function formatGraphqlIdorCandidates(urls: string[], limit = 10): string {
  return urls
    .slice(0, limit)
    .map((u) => `  - ${u}`)
    .join('\n');
}

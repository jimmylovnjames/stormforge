// Map fingerprinted products → focused Nuclei template packs.

export interface NucleiTechArgs {
  templates: string;
  flags: string;
}

/** Product name (from fingerprint / httpx tech) → nuclei tags / template dirs. */
const TECH_TO_NUCLEI: Record<string, string[]> = {
  wordpress: ['wordpress', 'wp-plugin', 'cves'],
  php: ['php', 'cves', 'vulnerabilities'],
  drupal: ['drupal', 'cves'],
  nginx: ['nginx', 'misconfiguration', 'cves'],
  apache: ['apache', 'misconfiguration', 'cves'],
  'microsoft-iis': ['iis', 'microsoft', 'cves'],
  express: ['nodejs', 'misconfiguration', 'exposures'],
  'asp.net': ['asp', 'microsoft', 'cves'],
  graphql: ['graphql', 'exposures'],
  'graphql yoga': ['graphql', 'exposures'],
  'apollo graphql': ['graphql', 'exposures'],
  'apollo server': ['graphql', 'exposures'],
  hasura: ['graphql', 'hasura', 'exposures'],
  graphiql: ['graphql', 'exposures'],
  'graphql playground': ['graphql', 'exposures'],
  'swagger ui': ['swagger', 'exposures', 'misconfiguration'],
  swagger: ['swagger', 'exposures'],
  openapi: ['swagger', 'exposures'],
  redoc: ['swagger', 'exposures'],
  jwt: ['token', 'jwt', 'exposures'],
  oauth: ['oauth', 'token', 'exposures'],
  cloudflare: ['cloudflare', 'misconfiguration'],
  jquery: ['cves'],
};

const GENERIC = ['cves', 'vulnerabilities', 'misconfiguration', 'exposures'];

/** Normalize product labels for lookup. */
export function normalizeProduct(product: string): string {
  return product.trim().toLowerCase().replace(/_/g, ' ');
}

export function templatesForProducts(products: string[]): string {
  const tags = new Set<string>();
  for (const p of products) {
    const key = normalizeProduct(p);
    const mapped = TECH_TO_NUCLEI[key];
    if (mapped) for (const t of mapped) tags.add(t);
    // Soft alias: anything containing "graphql"
    if (key.includes('graphql')) for (const t of TECH_TO_NUCLEI.graphql!) tags.add(t);
    if (key.includes('wordpress') || key === 'wp') for (const t of TECH_TO_NUCLEI.wordpress!) tags.add(t);
  }
  if (!tags.size) for (const t of GENERIC) tags.add(t);
  return [...tags].slice(0, 10).join(',');
}

export function nucleiArgsForTech(products: string[]): NucleiTechArgs {
  const templates = templatesForProducts(products);
  const focused = templates !== GENERIC.join(',');
  return {
    templates,
    flags: focused
      ? '-severity critical,high,medium -silent -c 25'
      : '-severity critical,high -silent -c 20',
  };
}

/** Pull product names from finding evidence / title (httpx tech lines, fingerprint). */
export function productsFromFindingText(...parts: Array<string | undefined>): string[] {
  const blob = parts.filter(Boolean).join('\n');
  if (!blob) return [];
  const out: string[] = [];
  // Comma / pipe separated tech lists from httpx
  for (const chunk of blob.split(/[\n,|]/)) {
    const t = chunk.trim();
    if (t.length >= 2 && t.length < 40 && /^[A-Za-z][A-Za-z0-9 ._+-]*$/.test(t)) {
      out.push(t);
    }
  }
  // Known keywords even if embedded
  for (const known of Object.keys(TECH_TO_NUCLEI)) {
    if (new RegExp(`\\b${known.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(blob)) {
      out.push(known);
    }
  }
  return [...new Set(out)].slice(0, 12);
}

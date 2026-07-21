// Map fingerprinted products → Worker GET path packs for heuristic planning.

import { normalizeProduct } from './tech-templates.js';

export { normalizeProduct };

/** Product name → high-signal paths the Worker can probe safely (GET/HEAD). */
const TECH_TO_PATHS: Record<string, string[]> = {
  wordpress: [
    '/wp-json/wp/v2/users',
    '/wp-json/',
    '/wp-login.php',
    '/xmlrpc.php',
    '/wp-config.php.bak',
    '/wp-content/debug.log',
  ],
  php: ['/phpinfo.php', '/info.php', '/.env', '/config.php.bak'],
  drupal: ['/user/1', '/admin/reports/status', '/CHANGELOG.txt', '/core/install.php'],
  nginx: ['/server-status', '/nginx_status', '/.htpasswd'],
  apache: ['/server-status', '/server-info', '/.htaccess'],
  'microsoft iis': ['/web.config', '/iisstart.htm', '/aspnet_client/'],
  'microsoft-iis': ['/web.config', '/iisstart.htm'],
  express: ['/api/auth/session', '/api/session', '/debug', '/.env'],
  node: ['/api/auth/session', '/_next/data', '/.env'],
  next: ['/_next/data', '/api/auth/session', '/api/auth/csrf'],
  'asp.net': ['/elmah.axd', '/trace.axd', '/web.config', '/api/values'],
  spring: ['/actuator', '/actuator/env', '/actuator/health', '/actuator/mappings', '/jolokia'],
  'spring boot': ['/actuator', '/actuator/env', '/actuator/beans', '/jolokia'],
  java: ['/actuator', '/jolokia', '/manager/html'],
  django: ['/admin/', '/__debug__/', '/api/schema/', '/static/admin/'],
  rails: ['/rails/info/properties', '/rails/mailers', '/sidekiq'],
  graphql: ['/graphql', '/api/graphql', '/graphiql', '/playground', '/v1/graphql'],
  'graphql yoga': ['/graphql', '/graphiql'],
  'apollo graphql': ['/graphql', '/api/graphql'],
  'apollo server': ['/graphql'],
  hasura: ['/v1/graphql', '/v1/metadata', '/console'],
  graphiql: ['/graphiql', '/graphql'],
  'graphql playground': ['/playground', '/graphql'],
  'swagger ui': ['/swagger.json', '/swagger-ui/', '/v3/api-docs', '/openapi.json'],
  swagger: ['/swagger.json', '/v2/api-docs', '/openapi.json'],
  openapi: ['/openapi.json', '/v3/api-docs', '/api-docs'],
  redoc: ['/redoc', '/openapi.json'],
  jwt: ['/.well-known/jwks.json', '/oauth/token', '/api/auth/session'],
  oauth: [
    '/.well-known/openid-configuration',
    '/oauth/authorize',
    '/oauth/token',
    '/oauth2/authorize',
  ],
  oidc: ['/.well-known/openid-configuration', '/.well-known/jwks.json', '/oauth/authorize'],
  openid: ['/.well-known/openid-configuration', '/.well-known/jwks.json'],
  saml: ['/saml/metadata', '/sso/saml/metadata', '/auth/saml/metadata'],
  cloudflare: ['/.well-known/security.txt'],
};

const CAP = 24;

/** Paths to probe for a set of fingerprinted products. */
export function pathsForProducts(products: string[]): string[] {
  const out = new Set<string>();
  for (const p of products) {
    const key = normalizeProduct(p);
    const mapped = TECH_TO_PATHS[key];
    if (mapped) for (const path of mapped) out.add(path);

    // Soft aliases
    if (key.includes('wordpress') || key === 'wp') {
      for (const path of TECH_TO_PATHS.wordpress!) out.add(path);
    }
    if (key.includes('graphql')) {
      for (const path of TECH_TO_PATHS.graphql!) out.add(path);
    }
    if (key.includes('spring')) {
      for (const path of TECH_TO_PATHS.spring!) out.add(path);
    }
    if (key.includes('openid') || key.includes('oidc')) {
      for (const path of TECH_TO_PATHS.oidc!) out.add(path);
    }
    if (key.includes('saml')) {
      for (const path of TECH_TO_PATHS.saml!) out.add(path);
    }
    if (key.includes('iis')) {
      for (const path of TECH_TO_PATHS['microsoft iis']!) out.add(path);
    }
  }
  return [...out].slice(0, CAP);
}

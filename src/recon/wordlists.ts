// Conservative, high-signal path wordlist for exposed-file / misconfig recon.
//
// Deliberately small and non-aggressive: these are common accidental exposures,
// not a brute-force dictionary. Extend via ScanRequest.extraPaths.

export const SENSITIVE_PATHS: string[] = [
  '/.git/config',
  '/.git/HEAD',
  '/.env',
  '/.env.local',
  '/.env.production',
  '/config.json',
  '/config.yml',
  '/.DS_Store',
  '/backup.zip',
  '/backup.sql',
  '/db.sql',
  '/dump.sql',
  '/.aws/credentials',
  '/wp-config.php.bak',
  '/phpinfo.php',
  '/server-status',
  '/.svn/entries',
  '/.htaccess',
  '/robots.txt',
  '/sitemap.xml',
  '/security.txt',
  '/.well-known/security.txt',
  '/swagger.json',
  '/openapi.json',
  '/api-docs',
  '/graphql',
  '/actuator',
  '/actuator/env',
  '/actuator/health',
  '/metrics',
];

// Paths worth probing for CORS / auth behavior (API-ish surfaces).
export const API_PROBE_PATHS: string[] = [
  '/',
  '/api',
  '/api/v1',
  '/api/v2',
  '/login',
  '/admin',
  '/user',
  '/account',
];

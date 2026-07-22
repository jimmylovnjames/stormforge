// Exposed sensitive files (.git, .env, backups, actuators, etc.).
//
// Passive confirmation: a file is only flagged if the response looks like the
// real thing (status 200 + content signature), which avoids false positives
// from catch-all 200 pages. Never downloads/exfiltrates beyond the probe body.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

interface Signature {
  pathIncludes: string;
  title: string;
  severity: Finding['severity'];
  /** Body must match at least one of these to confirm. Empty = status-only. */
  bodyMarkers: RegExp[];
  remediation: string;
  cwe: string;
}

const SIGNATURES: Signature[] = [
  {
    pathIncludes: '/.git/',
    title: 'Exposed .git repository',
    severity: 'high',
    bodyMarkers: [/\[core\]/, /ref:\s*refs\/heads/, /^[0-9a-f]{40}$/m],
    remediation: 'Block access to the .git directory at the web server / CDN layer.',
    cwe: 'CWE-527',
  },
  {
    pathIncludes: '/.env',
    title: 'Exposed environment file',
    severity: 'critical',
    bodyMarkers: [/^[A-Z0-9_]+=.+/m],
    remediation: 'Remove the .env file from the web root and rotate any exposed secrets.',
    cwe: 'CWE-538',
  },
  {
    pathIncludes: '/.DS_Store',
    title: 'Exposed .DS_Store directory index',
    severity: 'low',
    bodyMarkers: [/Bud1/, /\x00\x00\x00\x01Bud1/],
    remediation: 'Remove .DS_Store files from deployment and block the pattern.',
    cwe: 'CWE-527',
  },
  {
    pathIncludes: '/actuator',
    title: 'Exposed Spring Boot Actuator endpoint',
    severity: 'medium',
    bodyMarkers: [/"_links"/, /"health"/, /"diskSpace"/, /"propertySources"/, /"activeProfiles"/],
    remediation: 'Restrict actuator endpoints to internal networks / require authentication.',
    cwe: 'CWE-16',
  },
  {
    pathIncludes: '/phpinfo',
    title: 'Exposed phpinfo() page',
    severity: 'medium',
    bodyMarkers: [/phpinfo\(\)/, /PHP Version/],
    remediation: 'Remove phpinfo pages from production.',
    cwe: 'CWE-200',
  },
  {
    pathIncludes: '.sql',
    title: 'Exposed SQL dump / backup',
    severity: 'high',
    bodyMarkers: [/INSERT INTO/i, /CREATE TABLE/i, /-- MySQL dump/i],
    remediation: 'Remove database dumps from the web root.',
    cwe: 'CWE-538',
  },
  {
    pathIncludes: '.bak',
    title: 'Exposed backup file',
    severity: 'high',
    bodyMarkers: [/DB_PASSWORD|DATABASE_URL|SECRET|API_KEY|BEGIN (RSA |OPENSSH )?PRIVATE KEY/i, /<\?php/i],
    remediation: 'Remove backup copies (*.bak) from the web root and rotate any leaked secrets.',
    cwe: 'CWE-530',
  },
  {
    pathIncludes: '/.aws/credentials',
    title: 'Exposed AWS credentials file',
    severity: 'critical',
    bodyMarkers: [/\[default\]/, /aws_access_key_id/i, /aws_secret_access_key/i],
    remediation: 'Remove AWS credential files from the web root and rotate keys immediately.',
    cwe: 'CWE-538',
  },
  {
    pathIncludes: '/server-status',
    title: 'Exposed Apache server-status',
    severity: 'medium',
    bodyMarkers: [/Apache Server Status/i, /Server uptime/i, /Total accesses/i],
    remediation: 'Restrict mod_status to internal networks.',
    cwe: 'CWE-200',
  },
  {
    pathIncludes: '/.svn/',
    title: 'Exposed Subversion metadata',
    severity: 'medium',
    bodyMarkers: [/dir\n/, /svn:/, /wc-ng/],
    remediation: 'Block access to .svn directories at the edge.',
    cwe: 'CWE-527',
  },
  {
    pathIncludes: '/.git-credentials',
    title: 'Exposed git credentials store',
    severity: 'critical',
    bodyMarkers: [/https?:\/\/[^:@\s/]+:[^@\s/]+@/],
    remediation: 'Remove .git-credentials from the web root and rotate the embedded credentials.',
    cwe: 'CWE-522',
  },
  {
    pathIncludes: '/.npmrc',
    title: 'Exposed .npmrc with auth token',
    severity: 'high',
    bodyMarkers: [/_authToken\s*=/, /_auth\s*=/, /:_password=/],
    remediation: 'Remove .npmrc from the web root and rotate the registry auth token.',
    cwe: 'CWE-538',
  },
  {
    pathIncludes: '/.htpasswd',
    title: 'Exposed .htpasswd credential file',
    severity: 'high',
    bodyMarkers: [/^[A-Za-z0-9._-]+:\$(?:apr1|2[aby]|1|5|6)\$/m, /^[A-Za-z0-9._-]+:\{SHA\}/m],
    remediation: 'Block access to .htpasswd at the web server / CDN layer and rotate affected passwords.',
    cwe: 'CWE-538',
  },
  {
    pathIncludes: '/.htaccess',
    title: 'Exposed .htaccess configuration',
    severity: 'low',
    bodyMarkers: [/RewriteEngine/i, /RewriteRule/i, /AuthType/i, /Require\s+(?:all|valid-user)/i, /<Files/i],
    remediation: 'Block access to .htaccess files at the web server / CDN layer.',
    cwe: 'CWE-527',
  },
  {
    pathIncludes: '/web.config',
    title: 'Exposed IIS web.config',
    severity: 'high',
    bodyMarkers: [/<configuration>/i, /<system\.web>/i, /<connectionStrings>/i, /<appSettings>/i],
    remediation: 'Block access to web.config at the web server layer and rotate any embedded connection strings.',
    cwe: 'CWE-538',
  },
  {
    pathIncludes: '/id_rsa',
    title: 'Exposed SSH private key',
    severity: 'critical',
    bodyMarkers: [/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
    remediation: 'Remove the private key from the web root and rotate the key pair immediately.',
    cwe: 'CWE-312',
  },
  {
    pathIncludes: '/config.json',
    title: 'Exposed application config file',
    severity: 'medium',
    bodyMarkers: [
      /"(?:db_password|database_url|password|secret|api[_-]?key|private[_-]?key|access[_-]?token|client[_-]?secret)"\s*:/i,
    ],
    remediation: 'Do not serve config files containing secrets; move sensitive values to server-side secret storage and rotate.',
    cwe: 'CWE-538',
  },
  {
    pathIncludes: '/config.yml',
    title: 'Exposed application config file',
    severity: 'medium',
    bodyMarkers: [
      /^\s*(?:db_password|database_url|password|secret|api[_-]?key|private[_-]?key|access[_-]?token|client[_-]?secret)\s*:/im,
    ],
    remediation: 'Do not serve config files containing secrets; move sensitive values to server-side secret storage and rotate.',
    cwe: 'CWE-538',
  },
  {
    pathIncludes: '/docker-compose',
    title: 'Exposed docker-compose file',
    severity: 'medium',
    bodyMarkers: [/^\s*services\s*:/im, /image\s*:/i, /environment\s*:/i],
    remediation: 'Remove docker-compose files from the web root; they leak service topology and often embedded secrets.',
    cwe: 'CWE-538',
  },
];

export const exposedFilesCheck: Check = {
  id: 'exposed-files',
  title: 'Exposed sensitive files',
  cwe: 'CWE-538',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || probe.status !== 200) return [];
    const path = safePath(probe.finalUrl ?? probe.url);

    for (const sig of SIGNATURES) {
      if (!path.includes(sig.pathIncludes)) continue;
      const confirmed =
        sig.bodyMarkers.length === 0 || sig.bodyMarkers.some((re) => re.test(probe.body));
      if (!confirmed) continue;

      return [
        {
          id: makeFindingId(this.id, probe.url, sig.pathIncludes),
          checkId: this.id,
          title: sig.title,
          severity: sig.severity,
          target: probe.url,
          description: `${sig.title} confirmed at an in-scope URL. Sensitive files served to the public can leak source code, credentials, or internal data.`,
          evidence: `URL: ${probe.url}\nStatus: 200\nBody signature matched (first 200 chars): ${probe.body.slice(0, 200).replace(/\s+/g, ' ')}`,
          reproduction: [`Fetch ${probe.url}`, 'Confirm the response is the real file (matches the signature above)'],
          remediation: sig.remediation,
          cwe: sig.cwe,
          references: [`https://cwe.mitre.org/data/definitions/${sig.cwe.replace('CWE-', '')}.html`],
          needsManualReview: false,
          discoveredAt: new Date().toISOString(),
        },
      ];
    }
    return [];
  },
};

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

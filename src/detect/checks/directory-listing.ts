// Open directory listing / autoindex exposure.
//
// Passive: confirms an auto-generated index page (Apache mod_autoindex, nginx
// autoindex, IIS, Tomcat) rather than an application page. Severity is raised
// when the listing itself contains sensitive-looking entries.

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';

const INDEX_TITLE = /<title>\s*Index of \/[^<]*<\/title>/i;
const INDEX_HEADING = /<h1>\s*Index of \/[^<]*<\/h1>/i;
const APACHE_AUTOINDEX = /<a href="[^"]*">Parent Directory<\/a>|Apache\/[\d.]+.*Server at/i;
const NGINX_AUTOINDEX = /<hr><pre><a href="\.\.\/">\.\.<\/a>/i;
const IIS_LISTING = /<pre>.*<A HREF=".*">\[To Parent Directory\]<\/A>/is;
const TOMCAT_LISTING = /<title>\s*Directory Listing For \//i;

const SENSITIVE_ENTRY =
  /href="[^"]*\.(?:sql|env|bak|old|zip|tar|gz|tgz|7z|pem|key|p12|pfx|conf|config|ini|log|backup|db|sqlite)(?:["?])/i;
const SENSITIVE_DIR = /href="[^"]*(?:\.git|\.svn|backup|backups|dump|dumps|private|secret|admin)\/?"/i;

export const directoryListingCheck: Check = {
  id: 'directory-listing',
  title: 'Open directory listing (autoindex)',
  cwe: 'CWE-548',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 300) return [];
    const ct = (probe.headers['content-type'] ?? '').toLowerCase();
    if (ct && !ct.includes('text/html') && !ct.includes('text/plain')) return [];

    const body = probe.body;
    const hasTitle = INDEX_TITLE.test(body) || INDEX_HEADING.test(body) || TOMCAT_LISTING.test(body);
    const server =
      (APACHE_AUTOINDEX.test(body) && 'Apache mod_autoindex') ||
      (NGINX_AUTOINDEX.test(body) && 'nginx autoindex') ||
      (IIS_LISTING.test(body) && 'IIS directory browsing') ||
      (TOMCAT_LISTING.test(body) && 'Tomcat directory listing') ||
      '';

    // Require BOTH an index title/heading and an autoindex structural marker,
    // or an unambiguous server-specific listing, to avoid flagging app pages.
    const confirmed = (hasTitle && !!server) || IIS_LISTING.test(body) || TOMCAT_LISTING.test(body);
    if (!confirmed) return [];

    const sensitive = SENSITIVE_ENTRY.test(body) || SENSITIVE_DIR.test(body);
    const severity: Finding['severity'] = sensitive ? 'medium' : 'low';
    const label = server || 'directory listing';

    return [
      {
        id: makeFindingId(this.id, probe.url, sensitive ? 'sensitive' : 'listing'),
        checkId: this.id,
        title: sensitive
          ? `Open directory listing exposing sensitive files (${label})`
          : `Open directory listing (${label})`,
        severity,
        target: probe.url,
        description: sensitive
          ? `An open ${label} at this path lists directory contents including sensitive-looking files (archives, backups, keys, configs). Attackers can enumerate and download them directly.`
          : `An open ${label} at this path lets anyone enumerate directory contents, revealing files and structure not meant to be discoverable.`,
        evidence: `URL: ${probe.url}\nStatus: 200\nListing type: ${label}\nBody preview: ${body.slice(0, 240).replace(/\s+/g, ' ')}`,
        reproduction: [
          `curl -s '${probe.url}'`,
          `Confirm the response is an auto-generated ${label} (not an application page)`,
          sensitive ? 'Note the sensitive entries listed; verify manually before reporting' : 'Review listed entries for sensitive files',
        ],
        remediation:
          'Disable automatic directory indexing (Apache: `Options -Indexes`; nginx: `autoindex off`; IIS: disable Directory Browsing) and add an index document.',
        cwe: 'CWE-548',
        references: [
          'https://cwe.mitre.org/data/definitions/548.html',
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
        ],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: sensitive ? 0.82 : 0.7,
        submitReady: false,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      },
    ];
  },
};

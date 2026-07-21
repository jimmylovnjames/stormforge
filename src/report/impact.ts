// Shared impact copy for report drafts and bounty templates.

import type { Finding } from '../types.js';

export function impactForFinding(f: Finding): string {
  if (f.cwe === 'CWE-639') {
    return 'Broken object-level authorization (IDOR) can expose or manipulate other users’ objects by changing predictable identifiers — often leading to bulk personal data disclosure.';
  }
  if (f.checkId === 'subdomain-takeover') {
    return 'A dangling DNS CNAME lets an attacker claim the upstream service and host attacker-controlled content on a trusted subdomain — often leading to cookie theft, OAuth takeover, or phishing.';
  }
  if (f.cwe === 'CWE-284') {
    return 'Missing or ineffective authorization on authenticated/admin surfaces can grant anonymous callers access to account data or privileged operations.';
  }
  if (f.cwe === 'CWE-347') {
    return 'Acceptance or issuance of weak JWTs (alg=none / empty signature) can allow forged identity claims and full authentication bypass.';
  }
  if (f.cwe === 'CWE-798') {
    return 'Hard-coded or publicly served credentials can be extracted by anyone who can fetch the asset, enabling cloud takeover, data-store access, or abuse of third-party APIs until the secret is rotated.';
  }
  if (f.cwe === 'CWE-312') {
    return 'Cleartext credentials (connection strings, embedded basic-auth URLs) in HTTP responses expose infrastructure secrets and often unlock direct database or message-bus access.';
  }
  if (f.cwe === 'CWE-770') {
    return 'Missing or weak rate limiting on authentication and token endpoints enables credential stuffing, OTP/password guessing, and request floods that degrade availability.';
  }
  if (f.cwe === 'CWE-79') {
    return 'Cross-site scripting lets attackers execute script in victims’ browsers, steal sessions, deface content, or pivot to further account takeover.';
  }
  if (f.cwe === 'CWE-94') {
    return 'Server-side template injection can escalate from expression evaluation to remote code execution depending on the template engine and sandbox.';
  }
  if (f.cwe === 'CWE-209') {
    return 'Verbose error messages disclose implementation details that help attackers refine injection and template attacks.';
  }
  if (f.cwe === 'CWE-215') {
    return 'Exposed debug/diagnostic consoles often leak secrets, environment variables, and remote code execution gadgets.';
  }
  if (f.cwe === 'CWE-601') {
    return 'Open redirects enable phishing and token/session theft by sending users from a trusted domain to an attacker-controlled site.';
  }
  if (f.cwe === 'CWE-918') {
    return 'Server-side request forgery can reach internal services and cloud metadata endpoints, often yielding credentials and full environment compromise.';
  }
  if (f.cwe === 'CWE-78') {
    return 'OS command injection allows attackers to execute system commands on the server, typically leading to full remote code execution and host takeover.';
  }
  if (f.cwe === 'CWE-22') {
    return 'Path traversal / LFI lets attackers read sensitive files (credentials, source, keys) and often chains into remote code execution.';
  }
  if (f.cwe === 'CWE-644') {
    return 'Host header injection and cache poisoning can hijack password-reset links, poison CDN caches, and route victims to attacker infrastructure.';
  }
  if (f.cwe === 'CWE-89') {
    return 'SQL injection can disclose or modify database contents, bypass authentication, and in severe cases lead to remote code execution via database features.';
  }
  if (f.cwe === 'CWE-113') {
    return 'CRLF / HTTP response splitting enables session fixation, cache poisoning, and cross-site scripting via attacker-controlled response headers.';
  }
  if (f.cwe === 'CWE-1321') {
    return 'Prototype pollution can escalate into authentication bypass, remote code execution, or denial of service through polluted object gadgets.';
  }
  if (f.cwe === 'CWE-915') {
    return 'Mass assignment lets attackers set privileged model fields (roles, flags) and escalate access without a direct authorization flaw.';
  }
  if (f.cwe === 'CWE-200') {
    return 'Public object-store listings expose file keys and often leak backups, credentials, source archives, and personal data at scale.';
  }
  if (f.cwe === 'CWE-444') {
    return 'Web cache deception can store a victim’s authenticated response under a static URL, letting attackers retrieve private account data from shared caches.';
  }

  switch (f.severity) {
    case 'critical':
      return 'If confirmed, this issue could lead to full compromise of the affected asset or exposure of highly sensitive data.';
    case 'high':
      return 'This issue could allow significant unauthorized access or data exposure.';
    case 'medium':
      return 'This issue weakens the security posture and could be chained with others for greater impact.';
    case 'low':
      return 'This is a hardening gap with limited direct impact but worth remediating.';
    case 'info':
      return 'Informational — documents a deviation from best practice.';
    default: {
      const _exhaustive: never = f.severity;
      return `Severity ${_exhaustive}`;
    }
  }
}

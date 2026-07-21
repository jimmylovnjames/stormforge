// Passive secret / credential scanner for HTTP responses.
//
// Scans response bodies and secret-bearing headers (Set-Cookie, Authorization
// echoes, etc.) for high-signal credential patterns. Never validates or uses
// discovered secrets. Provider-specific matches are high/critical severity.

import type { Check, Finding, ProbeResult, Severity } from '../types.js';
import { makeFindingId } from '../findings/id.js';
import { SECRET_LEAK_PATHS } from './wordlists.js';

export interface SecretRule {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  /** CWE-798 = hard-coded credential; CWE-312 = cleartext storage/transmission. */
  cwe: 'CWE-312' | 'CWE-798';
  /**
   * true = pattern is specific enough that a match is a confirmed exposure
   * shape (still rotate/verify live-ness out of band).
   */
  confirmedShape: boolean;
}

const MAX_MATCHES_PER_RULE = 5;

/**
 * Patterns intentionally specific to keep false positives low.
 * Prefer vendor prefixes / URI schemes over generic "password=" alone.
 */
export const SECRET_RULES: SecretRule[] = [
  // ── Cloud / AWS ──────────────────────────────────────────────────────────
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    severity: 'critical',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key assignment',
    regex:
      /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secretAccessKey)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: 'critical',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'aws-session-token',
    name: 'AWS Session Token assignment',
    regex: /(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*['"]([A-Za-z0-9/+=]{20,})['"]/gi,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },

  // ── Database connection strings ──────────────────────────────────────────
  {
    id: 'postgres-uri',
    name: 'PostgreSQL connection URI',
    regex: /\bpostgres(?:ql)?:\/\/[^\s'"]{8,}/gi,
    severity: 'critical',
    cwe: 'CWE-312',
    confirmedShape: true,
  },
  {
    id: 'mysql-uri',
    name: 'MySQL connection URI',
    regex: /\bmysql:\/\/[^\s'"]{8,}/gi,
    severity: 'critical',
    cwe: 'CWE-312',
    confirmedShape: true,
  },
  {
    id: 'mongodb-uri',
    name: 'MongoDB connection URI',
    regex: /\bmongodb(?:\+srv)?:\/\/[^\s'"]{8,}/gi,
    severity: 'critical',
    cwe: 'CWE-312',
    confirmedShape: true,
  },
  {
    id: 'redis-uri',
    name: 'Redis connection URI',
    regex: /\bredis:\/\/[^\s'"]{6,}/gi,
    severity: 'high',
    cwe: 'CWE-312',
    confirmedShape: true,
  },
  {
    id: 'amqp-uri',
    name: 'AMQP / RabbitMQ connection URI',
    regex: /\bamqps?:\/\/[^\s'"]{8,}/gi,
    severity: 'high',
    cwe: 'CWE-312',
    confirmedShape: true,
  },
  {
    id: 'jdbc-uri',
    name: 'JDBC database URL',
    regex: /\bjdbc:(?:mysql|postgresql|sqlserver|oracle):[^\s'"]{8,}/gi,
    severity: 'high',
    cwe: 'CWE-312',
    confirmedShape: true,
  },

  // ── Vendor API tokens ────────────────────────────────────────────────────
  {
    id: 'google-api-key',
    name: 'Google API Key',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g,
    severity: 'critical',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'slack-webhook',
    name: 'Slack Incoming Webhook',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'stripe-live',
    name: 'Stripe Live Secret Key',
    regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g,
    severity: 'critical',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'stripe-test',
    name: 'Stripe Test Secret Key',
    regex: /\bsk_test_[0-9a-zA-Z]{24,}\b/g,
    severity: 'medium',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'github-token',
    name: 'GitHub Token',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    severity: 'critical',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'gitlab-token',
    name: 'GitLab Token',
    regex: /\bglpat-[A-Za-z0-9\-_]{20,}\b/g,
    severity: 'critical',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'npm-token',
    name: 'npm access token',
    regex: /\bnpm_[A-Za-z0-9]{36,}\b/g,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'openai-key',
    name: 'OpenAI API Key',
    // Exclude Anthropic sk-ant-* which is matched separately.
    regex: /\bsk-(?!ant-)[A-Za-z0-9]{20,}(?:T3BlbkFJ[A-Za-z0-9]{20,})?\b/g,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API Key',
    regex: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API Key',
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'twilio-sid',
    name: 'Twilio Account SID',
    regex: /\bAC[0-9a-f]{32}\b/g,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'mailgun-key',
    name: 'Mailgun API Key',
    regex: /\bkey-[0-9a-zA-Z]{32}\b/g,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'discord-webhook',
    name: 'Discord Webhook URL',
    regex: /https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'heroku-key',
    name: 'Heroku API Key',
    regex: /\b(?:heroku[_-]?api[_-]?key)\s*[=:]\s*['"]?[0-9a-fA-F-]{36}['"]?/gi,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'firebase-key',
    name: 'Firebase / GCP private key marker',
    regex: /"type"\s*:\s*"service_account"/g,
    severity: 'critical',
    cwe: 'CWE-798',
    confirmedShape: true,
  },

  // ── Private keys / basic auth ────────────────────────────────────────────
  {
    id: 'private-key',
    name: 'Private Key Block',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
    cwe: 'CWE-798',
    confirmedShape: true,
  },
  {
    id: 'basic-auth-uri',
    name: 'URL with embedded basic-auth credentials',
    regex: /\bhttps?:\/\/[^\/\s:'"]+:[^\/\s:'"]{4,}@[^\s'"]+/gi,
    severity: 'high',
    cwe: 'CWE-312',
    confirmedShape: true,
  },

  // ── Hardcoded assignments (slightly noisier → high on leak paths) ───────
  {
    id: 'generic-api-key-assign',
    name: 'Hardcoded API key / secret assignment',
    regex:
      /(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|secret[_-]?key)\s*[=:]\s*['"][A-Za-z0-9\-_+/=]{16,}['"]/gi,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: false,
  },
  {
    id: 'password-assign',
    name: 'Hardcoded password assignment',
    regex: /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    severity: 'high',
    cwe: 'CWE-798',
    confirmedShape: false,
  },
];

/** Redact the middle of a token so evidence is safe to store/paste. */
export function redact(token: string): string {
  const trimmed = token.length > 120 ? `${token.slice(0, 120)}…` : token;
  if (trimmed.length <= 8) return `${trimmed[0] ?? ''}***`;
  return `${trimmed.slice(0, 4)}…${trimmed.slice(-4)} (len ${token.length})`;
}

/** True when the probe URL looks like a known secret-leak path. */
export function isSecretLeakPath(url: string): boolean {
  let path: string;
  try {
    path = new URL(url).pathname;
  } catch {
    path = url;
  }
  const lower = path.toLowerCase();
  return SECRET_LEAK_PATHS.some((p) => lower === p.toLowerCase() || lower.endsWith(p.toLowerCase()));
}

function bumpSeverity(base: Severity, onLeakPath: boolean, confirmed: boolean): Severity {
  // Confirmed provider shapes stay at least high; leak-path generic assign → high already.
  if (base === 'critical') return 'critical';
  if (base === 'high') return onLeakPath || confirmed ? 'high' : 'high';
  if (base === 'medium' && onLeakPath) return 'high';
  if (base === 'low' && onLeakPath) return 'medium';
  return base;
}

/** Collect text surfaces to scan (body + secret-bearing headers). */
export function collectSecretHaystacks(probe: ProbeResult): { source: string; text: string }[] {
  const out: { source: string; text: string }[] = [];
  if (probe.body) out.push({ source: 'body', text: probe.body });
  for (const h of ['set-cookie', 'authorization', 'x-api-key', 'x-amz-security-token', 'proxy-authorization'] as const) {
    const v = probe.headers[h];
    if (v) out.push({ source: `header:${h}`, text: v });
  }
  return out;
}

export function scanSecrets(probe: ProbeResult): Finding[] {
  if (probe.error) return [];
  const haystacks = collectSecretHaystacks(probe);
  if (haystacks.length === 0) return [];

  const onLeakPath = isSecretLeakPath(probe.finalUrl ?? probe.url);
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const rule of SECRET_RULES) {
    let matchCount = 0;
    for (const { source, text } of haystacks) {
      rule.regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = rule.regex.exec(text)) !== null) {
        const token = m[0];
        const dedupe = `${rule.id}:${token}:${source}`;
        if (seen.has(dedupe)) continue;
        seen.add(dedupe);
        matchCount++;
        if (matchCount > MAX_MATCHES_PER_RULE) break;

        const severity = bumpSeverity(rule.severity, onLeakPath, rule.confirmedShape);
        const confirmed = rule.confirmedShape;

        findings.push({
          id: makeFindingId('secret-exposure', probe.url, `${rule.id}:${redact(token)}`),
          checkId: 'secret-exposure',
          title: confirmed
            ? `${rule.name} exposed in HTTP response`
            : `Possible ${rule.name} exposed in HTTP response`,
          severity,
          target: probe.url,
          description: confirmed
            ? `A ${rule.name} matching a known credential shape was found in the ${source} of an in-scope response${onLeakPath ? ' on a high-risk config/secret path' : ''}. Treat as a live secret until rotated.`
            : `A string matching ${rule.name} was found in the ${source} of an in-scope response${onLeakPath ? ' on a high-risk config/secret path' : ''}. Confirm it is not a placeholder before reporting.`,
          evidence: `Pattern: ${rule.name} (${rule.id})\nSource: ${source}\nLeak path: ${onLeakPath}\nRedacted match: ${redact(token)}\nURL: ${probe.url}`,
          reproduction: [
            `Fetch ${probe.url}`,
            `Inspect ${source} for a value matching ${rule.name}`,
            'Confirm out of band (without authenticating with the secret) whether it is live, then rotate',
          ],
          remediation:
            'Remove the secret from client-served assets and public config, rotate the credential immediately, and load secrets from a server-side secret manager.',
          cwe: rule.cwe,
          references: [
            `https://cwe.mitre.org/data/definitions/${rule.cwe.replace('CWE-', '')}.html`,
            'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key',
          ],
          // Confirmed vendor shapes still need live-ness check, but are not "maybe a false regex hit".
          needsManualReview: !confirmed,
          discoveredAt: new Date().toISOString(),
        });
      }
      if (matchCount > MAX_MATCHES_PER_RULE) break;
    }
  }
  return findings;
}

/** Check wrapper so secret scanning appears in /api/checks and the registry. */
export const secretsExposureCheck: Check = {
  id: 'secret-exposure',
  title: 'Secret / credential exposure',
  cwe: 'CWE-798',
  run(probe: ProbeResult): Finding[] {
    return scanSecrets(probe);
  },
};

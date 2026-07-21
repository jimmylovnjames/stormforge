// Natural-language orchestration commands for Grok mobile / chat UI.
// AUTHORIZED TARGETS ONLY — never implies authorization.

export type OrchestrateIntent =
  | 'help'
  | 'plan'
  | 'scan'
  | 'status'
  | 'findings'
  | 'report'
  | 'audit'
  | 'dispatch'
  | 'tasks';

export type ToolNameLite =
  | 'nmap'
  | 'nuclei'
  | 'httpx'
  | 'subfinder'
  | 'katana'
  | 'ffuf'
  | 'sqlmap'
  | 'gobuster';

export interface ParsedCommand {
  intent: OrchestrateIntent;
  message: string;
  targets?: string[];
  inScope?: string[];
  outOfScope?: string[];
  program?: string;
  platform?: 'hackerone' | 'bugcrowd' | 'immunefi' | 'intigriti' | 'generic';
  authorized: boolean;
  scanId?: string;
  tool?: ToolNameLite;
  error?: string;
  replyHint?: string;
}

const TOOLS = new Set<ToolNameLite>([
  'nmap',
  'nuclei',
  'httpx',
  'subfinder',
  'katana',
  'ffuf',
  'sqlmap',
  'gobuster',
]);

const PLATFORMS = new Set(['hackerone', 'bugcrowd', 'immunefi', 'intigriti', 'generic']);

/**
 * Parse a short operator message into a structured orchestrate intent.
 * Requires explicit `authorized` / `authorized=true` for mutating actions.
 */
export function parseOrchestrateMessage(raw: string): ParsedCommand {
  const message = (raw || '').trim();
  const lower = message.toLowerCase();

  if (!message || /^(help|\?|commands|hi|hello)\b/.test(lower)) {
    return { intent: 'help', message, authorized: false };
  }

  const authorized = /\bauthorized(=true)?\b/i.test(message) && !/\bauthorized=false\b/i.test(message);
  const program = kv(message, 'program') || undefined;
  const platformRaw = (kv(message, 'platform') || '').toLowerCase();
  const platform: ParsedCommand['platform'] = PLATFORMS.has(platformRaw)
    ? (platformRaw as ParsedCommand['platform'])
    : 'generic';
  const scanId =
    kv(message, 'scanId') ||
    kv(message, 'scan') ||
    message.match(/\b(?:status|tasks)\s+(?:for\s+)?([a-z0-9-]{6,})\b/i)?.[1];

  const urls = extractUrls(message);
  const hosts = extractBareHosts(message);
  const targets = [...urls, ...hosts.map((h) => (h.includes('://') ? h : `https://${h}`))];
  const inScopeExplicit = csv(kv(message, 'inScope'));
  const outOfScope = csv(kv(message, 'outOfScope'));
  const inScope =
    inScopeExplicit.length > 0
      ? inScopeExplicit
      : deriveInScope(targets, message);

  // audit
  if (/^\s*audit\b/i.test(message) || /\bshow audit\b/i.test(lower)) {
    return { intent: 'audit', message, authorized, program };
  }

  // findings / report
  if (/^\s*findings\b/i.test(message) || /\bshow findings\b/i.test(lower)) {
    const prog = program || extractNamedArg(message, 'findings');
    if (!prog || /authorized|=/.test(prog)) {
      return { intent: 'findings', message, authorized, error: 'Usage: findings <program>' };
    }
    return { intent: 'findings', message, authorized, program: prog };
  }
  if (/^\s*report\b/i.test(message) || /\bshow report\b/i.test(lower)) {
    const prog = program || extractNamedArg(message, 'report');
    if (!prog || /authorized|=/.test(prog)) {
      return { intent: 'report', message, authorized, error: 'Usage: report <program>' };
    }
    return { intent: 'report', message, authorized, program: prog };
  }

  // status / tasks
  if (/^\s*tasks\b/i.test(message)) {
    if (!scanId) return { intent: 'tasks', message, authorized, error: 'Usage: tasks <scanId>' };
    return { intent: 'tasks', message, authorized, scanId };
  }
  if (/^\s*status\b/i.test(message)) {
    if (!scanId) return { intent: 'status', message, authorized, error: 'Usage: status <scanId>' };
    return { intent: 'status', message, authorized, scanId };
  }

  // dispatch <tool> <target>
  if (/^\s*dispatch\b/i.test(message) || /^\s*run\s+\w+\b/i.test(message)) {
    const toolMatch = message.match(/\b(dispatch|run)\s+(\w+)/i);
    const toolRaw = (toolMatch?.[2] || '').toLowerCase() as ToolNameLite;
    if (!TOOLS.has(toolRaw)) {
      return {
        intent: 'dispatch',
        message,
        authorized,
        error: `Unknown tool. Use: ${[...TOOLS].join(', ')}`,
      };
    }
    if (!authorized) {
      return {
        intent: 'dispatch',
        message,
        authorized: false,
        tool: toolRaw,
        targets,
        error: 'REFUSED: add "authorized" (and inScope) — StormForge will not dispatch without explicit authorization',
      };
    }
    if (!targets.length) {
      return { intent: 'dispatch', message, authorized, tool: toolRaw, error: 'Usage: dispatch httpx https://target authorized inScope=target.com program=x' };
    }
    return {
      intent: 'dispatch',
      message,
      authorized: true,
      tool: toolRaw,
      targets,
      inScope: inScope.length ? inScope : [hostOf(targets[0]!)],
      outOfScope,
      program: program || 'mobile-lab',
      platform,
    };
  }

  // plan / attack
  if (/\b(plan|attack|hunt|recon tools)\b/i.test(message)) {
    if (!authorized) {
      return {
        intent: 'plan',
        message,
        authorized: false,
        targets,
        error: 'REFUSED: mutating plan requires explicit "authorized" in the message',
      };
    }
    if (!targets.length) {
      return { intent: 'plan', message, authorized: true, error: 'Usage: plan https://target authorized program=x inScope=target.com' };
    }
    return {
      intent: 'plan',
      message,
      authorized: true,
      targets,
      inScope: inScope.length ? inScope : targets.map(hostOf),
      outOfScope,
      program: program || 'mobile-lab',
      platform,
    };
  }

  // passive scan
  if (/\b(scan|passive)\b/i.test(message)) {
    if (!authorized) {
      return {
        intent: 'scan',
        message,
        authorized: false,
        targets,
        error: 'REFUSED: scan requires explicit "authorized"',
      };
    }
    if (!targets.length) {
      return { intent: 'scan', message, authorized: true, error: 'Usage: scan https://api.target.com *.target.com authorized program=x' };
    }
    return {
      intent: 'scan',
      message,
      authorized: true,
      targets,
      inScope: inScope.length ? inScope : deriveInScope(targets, message),
      outOfScope,
      program: program || 'mobile-lab',
      platform,
    };
  }

  return {
    intent: 'help',
    message,
    authorized: false,
    error: 'Unknown command',
    replyHint: 'Try: help | plan … authorized | scan … authorized | findings <program> | status <scanId>',
  };
}

/** System / project instructions to paste into Grok (mobile Projects / custom instructions). */
export function buildGrokInstructions(baseUrl: string): string {
  const base = baseUrl.replace(/\/$/, '');
  return `You are the operator co-pilot for StormForge (authorized bug-bounty recon only).

BASE: ${base}
ORCHESTRATE: POST ${base}/api/orchestrate
HEADER: x-executor-secret: <SECRET the user provides>
HEADER: content-type: application/json
BODY: {"message":"<command>"}

Also: mobile UI ${base}/m — user can paste the same commands there.

Rules:
- NEVER invent authorization. The word "authorized" MUST appear in the command for plan/scan/dispatch.
- NEVER target hosts outside the user's stated inScope.
- Prefer short commands. After each action, summarize scanId / tasks / next step.
- For findings, ask for program id then call findings/report.
- Loop: plan/scan → remember scanId → tasks <scanId> (executor progress) → status <scanId> (passive DO) → findings <program>.
- status = passive Durable Object progress. tasks = remote executor queue for the same scanId (hybrid/plan/dispatch).
- Executor must be polling /api/tasks/poll or remote work stays pending.

Command cheat-sheet:
- help
- plan https://target.example authorized program=my-h1 inScope=*.example,target.example
- scan https://api.example *.example authorized program=my-h1
- dispatch httpx https://target.example authorized program=lab inScope=target.example
- status <scanId>
- tasks <scanId>
- findings <program>
- report <program>
- audit

If you cannot HTTP POST yourself, give the user the exact curl or tell them to open ${base}/m and paste the command.`;
}

export function helpText(baseUrl?: string): string {
  const base = baseUrl?.replace(/\/$/, '') || '';
  return [
    'StormForge mobile / Grok commands (AUTHORIZED ONLY):',
    '',
    '  help',
    '  plan https://target authorized program=lab inScope=target.com',
    '  scan https://api.target.com *.target.com authorized program=lab',
    '  dispatch httpx https://target authorized program=lab inScope=target.com',
    '  status <scanId>   ← passive scan DO',
    '  tasks <scanId>    ← executor queue (same scanId)',
    '  findings <program>',
    '  report <program>',
    '  audit',
    '',
    'Mutating commands REQUIRE the word "authorized".',
    'Hybrid tip: after scan/plan, run tasks <scanId> while the executor polls.',
    base ? `Orchestrate API: POST ${base}/api/orchestrate` : '',
    base ? `Mobile UI: ${base}/m` : '',
  ]
    .filter(Boolean)
    .join('\n');
}

function extractNamedArg(message: string, kind: 'findings' | 'report'): string | undefined {
  const re = new RegExp(
    `\\b(?:show\\s+)?${kind}(?:\\s+for)?\\s+([a-z0-9][a-z0-9._-]{1,63})\\b`,
    'i',
  );
  const m = message.match(re);
  return m?.[1];
}

function kv(message: string, key: string): string | null {
  const re = new RegExp(`\\b${key}=([^\\s]+)`, 'i');
  const m = message.match(re);
  return m?.[1] ? decodeURIComponent(m[1]) : null;
}

function csv(v: string | null): string[] {
  if (!v) return [];
  return v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function extractUrls(message: string): string[] {
  const out: string[] = [];
  const re = /https?:\/\/[^\s]+/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(message)) !== null) {
    out.push(m[0].replace(/[.,;)]+$/, ''));
  }
  return out;
}

function extractBareHosts(message: string): string[] {
  const out: string[] = [];
  // wildcards like *.acme.com
  for (const m of message.match(/\*\.[a-z0-9.-]+\.[a-z]{2,}/gi) || []) {
    out.push(m.toLowerCase());
  }
  // bare domains (not key=value)
  for (const m of message.match(/(?<![=/])\b[a-z0-9-]+(?:\.[a-z0-9-]+)+/gi) || []) {
    const h = m.toLowerCase();
    if (h.startsWith('program.') || h.includes('=')) continue;
    if (/^(status|tasks|findings|report|audit|help|plan|scan|dispatch|authorized)$/.test(h)) continue;
    if (message.includes(`https://${h}`) || message.includes(`http://${h}`)) continue;
    out.push(h);
  }
  return [...new Set(out)];
}

function deriveInScope(targets: string[], message: string): string[] {
  const wildcards = message.match(/\*\.[a-z0-9.-]+\.[a-z]{2,}/gi) || [];
  const hosts = targets.map(hostOf).filter(Boolean);
  return [...new Set([...wildcards.map((w) => w.toLowerCase()), ...hosts])];
}

function hostOf(target: string): string {
  try {
    const raw = target.includes('://') ? target : `https://${target}`;
    return new URL(raw).hostname.toLowerCase();
  } catch {
    return target.replace(/^\*\./, '').toLowerCase();
  }
}

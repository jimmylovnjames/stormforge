// Safe GET helpers for OS command-injection / RCE signal detection.
// Uses unique echo canaries and read-only probes only — never destructive
// payloads (no curl|sh, rm, wget, reverse shells).

/** Unique token produced only if `echo`/printf ran in a shell. */
export const CMD_CANARY = 'sfRce9f3a7c';

/**
 * Payloads that, if interpreted by a shell, emit CMD_CANARY.
 * Kept minimal and non-destructive.
 */
export const CMD_PAYLOADS = [
  `;echo ${CMD_CANARY}`,
  `|echo ${CMD_CANARY}`,
  `||echo ${CMD_CANARY}`,
  `&&echo ${CMD_CANARY}`,
  `\`${CMD_CANARY}\``, // backtick-only marker — weak alone
  `$(echo ${CMD_CANARY})`,
  `;printf ${CMD_CANARY}`,
  `|printf%20${CMD_CANARY}`, // may be double-encoded by URLSearchParams — prefer unencoded form
  `;echo%20${CMD_CANARY}`,
] as const;

/** Prefer these clean (pre-encode) payloads when building URLs. */
export const CMD_SAFE_PAYLOADS = [
  `;echo ${CMD_CANARY}`,
  `|echo ${CMD_CANARY}`,
  `$(echo ${CMD_CANARY})`,
  `;id`, // read-only proof commonly accepted in bug bounty
] as const;

/** Params often passed to ping/exec/diagnostic backends. */
export const CMD_PARAM_NAMES = [
  'cmd',
  'command',
  'exec',
  'execute',
  'run',
  'ping',
  'host',
  'ip',
  'dest',
  'target',
  'hostname',
  'domain',
  'query',
  'q',
  'input',
  'payload',
] as const;

/** Endpoints that historically shell out for diagnostics / admin tools. */
export const CMD_EXEC_PATHS: string[] = [
  '/ping',
  '/traceroute',
  '/trace',
  '/nslookup',
  '/dig',
  '/whois',
  '/exec',
  '/cmd',
  '/command',
  '/run',
  '/shell',
  '/system',
  '/diagnostic',
  '/diagnostics',
  '/tools/ping',
  '/tools/traceroute',
  '/admin/ping',
  '/admin/exec',
  '/admin/cmd',
  '/api/ping',
  '/api/exec',
  '/api/cmd',
  '/api/command',
  '/api/run',
  '/api/system',
  '/api/v1/ping',
  '/api/v1/exec',
  '/api/v1/cmd',
  '/cgi-bin/ping',
  '/cgi-bin/test',
];

export function buildCommandInjectionProbeUrls(baseUrl: string, maxParams = 2): string[] {
  const out: string[] = [];
  try {
    const params = CMD_PARAM_NAMES.slice(0, maxParams);
    for (const param of params) {
      for (const payload of CMD_SAFE_PAYLOADS.slice(0, 3)) {
        const u = new URL(baseUrl);
        for (const p of CMD_PARAM_NAMES) u.searchParams.delete(p);
        // Prefix with a benign host token some ping wrappers require.
        const value = param === 'ping' || param === 'host' || param === 'ip' || param === 'hostname'
          ? `127.0.0.1${payload}`
          : payload;
        u.searchParams.set(param, value);
        out.push(u.toString());
      }
    }
  } catch {
    return [];
  }
  return out;
}

export function urlCarriesCmdPayload(url: string): boolean {
  try {
    for (const v of new URL(url).searchParams.values()) {
      if (v.includes(CMD_CANARY)) return true;
      if (/[;&|`]|\$\(/.test(v)) return true;
    }
  } catch {
    return /[;&|`]|\$\(/.test(url) || url.includes(CMD_CANARY);
  }
  return false;
}

/**
 * Confirmed execution: canary appears in body AND the raw shell payload does
 * not (engine ran echo/printf rather than echoing the injection string).
 */
export function hasCommandExecutionCanary(body: string, probeUrl: string): boolean {
  if (!urlCarriesCmdPayload(probeUrl)) return false;
  if (!body.includes(CMD_CANARY)) return false;
  // Literal reflection of the payload is not execution.
  if (
    body.includes(`echo ${CMD_CANARY}`) ||
    body.includes(`echo%20${CMD_CANARY}`) ||
    body.includes(`$(echo ${CMD_CANARY})`) ||
    body.includes(`printf ${CMD_CANARY}`) ||
    body.includes(`;echo ${CMD_CANARY}`) ||
    body.includes(`|echo ${CMD_CANARY}`)
  ) {
    return false;
  }
  return true;
}

/** Shell / OS error signatures after a metachar probe. */
export function hasShellErrorSignal(body: string, probeUrl: string): boolean {
  if (!urlCarriesCmdPayload(probeUrl) && !urlHasShellMetachar(probeUrl)) return false;
  return (
    /\b(?:sh|bash|zsh|dash):\s(?:.+:\s)?(?:command not found|syntax error|unexpected EOF|Permission denied)/i.test(
      body,
    ) ||
    /\b\/bin\/(?:sh|bash):\s/i.test(body) ||
    /\bcmd\.exe\b/i.test(body) ||
    /'[^']+' is not recognized as an internal or external command/i.test(body) ||
    (/\bSyntaxError:.*unexpected token/i.test(body) && /[;&|]/.test(probeUrl)) ||
    (/\bWindows PowerShell\b/i.test(body) && /[;&|]/.test(probeUrl))
  );
}

function urlHasShellMetachar(url: string): boolean {
  try {
    for (const v of new URL(url).searchParams.values()) {
      if (/[;&|`]|\$\(/.test(v)) return true;
    }
  } catch {
    return /[;&|`]|\$\(/.test(url);
  }
  return false;
}

/**
 * Strong RCE signal: classic `id`/`whoami`/`uname` output when probe included
 * shell metacharacters (separate from our echo canary).
 */
export function hasOsCommandOutput(body: string, probeUrl: string): boolean {
  if (!urlHasShellMetachar(probeUrl) && !urlCarriesCmdPayload(probeUrl)) return false;
  return (
    /\buid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)/.test(body) ||
    /\bLinux\s+\S+\s+\d+\.\d+\.\d+.+\bx86_64\b/.test(body) ||
    /\bMicrosoft Windows \[Version\s+\d+/i.test(body)
  );
}

export function shouldProbeCommandInjection(probe: {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}): boolean {
  if (probe.error) return false;
  if (probe.status === 0) return false;
  const path = safePath(probe.url);
  if (CMD_EXEC_PATHS.some((p) => path === p || path.endsWith(p))) return true;
  const ct = (probe.headers['content-type'] ?? '').toLowerCase();
  if (
    ct.includes('text/html') &&
    /name=["'](?:cmd|command|exec|host|ip|ping)["']/i.test(probe.body)
  ) {
    return true;
  }
  if (/[?&](?:cmd|command|exec|ping|host)=/i.test(probe.url)) return true;
  return false;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

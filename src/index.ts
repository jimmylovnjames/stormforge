// StormForge C2 — Cloudflare Worker entry point.
//
// This Worker serves as the Command & Control brain:
// - Dashboard UI
// - Passive scan orchestration (existing)
// - Task queue for remote executor (NEW): /api/tasks/*
// - LLM-driven vuln planning
//
// The Worker NEVER runs offensive tools itself. It dispatches ToolTasks to
// a remote Node.js executor that polls /api/tasks/poll and submits results
// back via /api/tasks/complete.

import type { Env, ScanRequest, Scope, ToolTask, ToolTaskResult, ToolName, Severity } from './types.js';
import { ScanOrchestrator } from './do/scan-orchestrator.js';
import { partitionByScope, assertInScope } from './scope/scope-guard.js';
import { FindingsStore, summarizeSecretFindings } from './findings/store.js';
import { draftBountyAutomation, draftDisclosure } from './report/drafter.js';
import { listChecks } from './detect/registry.js';
import { DASHBOARD_HTML } from './dashboard-html.js';
import { planAttackSurface } from './planning/vuln-planner.js';
import { dispatchFollowUpsFromFindings } from './planning/dispatch-followups.js';
import { estimateCvss, sortByCvss } from './report/cvss.js';
import type { BountyPlatform } from './report/templates.js';
import {
  enrichFinding,
  findPromotionTarget,
  promoteWithToolConfirmation,
} from './findings/confidence.js';
import { shouldAutoDraft } from './findings/prioritize.js';
import type { Finding } from './types.js';
import { isCanaryToken, recordCanaryHit } from './recon/canary.js';
import { validateSession } from './recon/session.js';

export { ScanOrchestrator };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    try {
      // ─── Dashboard ───────────────────────────────────────────────────
      if (request.method === 'GET' && pathname === '/') {
        return new Response(DASHBOARD_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
      }

      // ─── Blind SSRF / OAST canary ─────────────────────────────────────
      const canaryMatch = pathname.match(/^\/api\/canary\/([a-fA-F0-9]{16,64})$/);
      if ((request.method === 'GET' || request.method === 'HEAD') && canaryMatch) {
        return await handleCanaryHit(canaryMatch[1], request, env);
      }

      // ─── Passive Scan (existing) ────────────────────────────────────
      if (request.method === 'POST' && pathname === '/api/scan') {
        return await handleStartScan(request, env);
      }

      const statusMatch = pathname.match(/^\/api\/scan\/([^/]+)\/status$/);
      if (request.method === 'GET' && statusMatch) {
        return await handleStatus(statusMatch[1], env);
      }

      const findingsMatch = pathname.match(/^\/api\/findings\/([^/]+)$/);
      if (request.method === 'GET' && findingsMatch) {
        const store = new FindingsStore(env.STORMFORGE_KV);
        const program = decodeURIComponent(findingsMatch[1]);
        const checkId = url.searchParams.get('checkId') ?? undefined;
        const minRaw = url.searchParams.get('minSeverity');
        const minSeverity = isSeverity(minRaw) ? minRaw : undefined;
        const findings =
          checkId || minSeverity
            ? await store.query(program, { checkId, minSeverity })
            : await store.getAll(program);
        return json({ findings, secrets: summarizeSecretFindings(findings) });
      }

      const reportMatch = pathname.match(/^\/api\/report\/([^/]+)$/);
      if (request.method === 'GET' && reportMatch) {
        return await handleReport(decodeURIComponent(reportMatch[1]), env);
      }

      const draftsMatch = pathname.match(/^\/api\/drafts\/([^/]+)$/);
      if (request.method === 'GET' && draftsMatch) {
        return await handleListDrafts(decodeURIComponent(draftsMatch[1]), env);
      }

      // GET /api/bounty/:program?platform=hackerone|immunefi — CVSS-ranked bounty packs
      const bountyMatch = pathname.match(/^\/api\/bounty\/([^/]+)$/);
      if (request.method === 'GET' && bountyMatch) {
        return await handleBountyPacks(decodeURIComponent(bountyMatch[1]), url, env);
      }

      // POST /api/bounty/generate — body: { findings?, program, platform, scope? }
      if (request.method === 'POST' && pathname === '/api/bounty/generate') {
        return await handleBountyGenerate(request, env);
      }

      if (request.method === 'GET' && pathname === '/api/checks') {
        return json({ checks: listChecks().map((c) => ({ id: c.id, title: c.title, cwe: c.cwe })) });
      }

      // ─── Task Queue: Executor Communication ─────────────────────────

      // POST /api/tasks/dispatch — LLM planner creates tasks for a target
      if (request.method === 'POST' && pathname === '/api/tasks/dispatch') {
        return await handleDispatch(request, env);
      }

      // GET /api/tasks/poll — Executor polls for pending tasks
      if (request.method === 'GET' && pathname === '/api/tasks/poll') {
        return await handlePoll(request, env);
      }

      // POST /api/tasks/complete — Executor submits results
      if (request.method === 'POST' && pathname === '/api/tasks/complete') {
        return await handleComplete(request, env);
      }

      // GET /api/tasks/status — View all tasks for a scan
      const taskStatusMatch = pathname.match(/^\/api\/tasks\/status\/([^/]+)$/);
      if (request.method === 'GET' && taskStatusMatch) {
        return await handleTaskStatus(taskStatusMatch[1], env);
      }

      // POST /api/plan-attack — LLM plans attack surface and auto-dispatches tasks
      if (request.method === 'POST' && pathname === '/api/plan-attack') {
        return await handlePlanAttack(request, env);
      }

      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: (e as Error).message }, 500);
    }
  },
};

// ─── Auth helper ──────────────────────────────────────────────────────────────

function authenticateExecutor(request: Request, env: Env): boolean {
  const secret = env.EXECUTOR_SECRET;
  if (!secret) return true; // No secret configured = open (dev mode)
  const header = request.headers.get('x-executor-secret') || '';
  return header === secret;
}

// ─── Task Queue Handlers ──────────────────────────────────────────────────────

async function handleDispatch(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as {
    scanId: string;
    tool: ToolName;
    target: string;
    args?: Record<string, string>;
    scope: Scope;
    timeoutSec?: number;
  };

  if (!body.scope?.authorized) {
    return json({ error: 'Scope not authorized' }, 403);
  }

  // Validate target is in scope
  try {
    assertInScope(body.target, body.scope);
  } catch (e) {
    return json({ error: `Target out of scope: ${(e as Error).message}` }, 403);
  }

  const task: ToolTask = {
    id: crypto.randomUUID(),
    scanId: body.scanId || crypto.randomUUID(),
    tool: body.tool,
    target: body.target,
    args: body.args || {},
    scope: body.scope,
    status: 'pending',
    timeoutSec: body.timeoutSec || 300,
    createdAt: new Date().toISOString(),
  };

  // Store in KV
  await env.STORMFORGE_KV.put(`task:${task.id}`, JSON.stringify(task));
  // Add to pending queue
  const queue = await getQueue(env);
  queue.push(task.id);
  await env.STORMFORGE_KV.put('task_queue:pending', JSON.stringify(queue));

  return json({ taskId: task.id, status: 'pending' });
}

async function handlePoll(request: Request, env: Env): Promise<Response> {
  if (!authenticateExecutor(request, env)) {
    return json({ error: 'Unauthorized' }, 401);
  }

  const queue = await getQueue(env);
  if (queue.length === 0) {
    return json({ tasks: [] });
  }

  // Grab up to 5 tasks at once
  const batch = queue.splice(0, 5);
  await env.STORMFORGE_KV.put('task_queue:pending', JSON.stringify(queue));

  const tasks: ToolTask[] = [];
  for (const id of batch) {
    const raw = await env.STORMFORGE_KV.get(`task:${id}`);
    if (raw) {
      const task = JSON.parse(raw) as ToolTask;
      task.status = 'running';
      await env.STORMFORGE_KV.put(`task:${id}`, JSON.stringify(task));
      tasks.push(task);
    }
  }

  return json({ tasks });
}

async function handleComplete(request: Request, env: Env): Promise<Response> {
  if (!authenticateExecutor(request, env)) {
    return json({ error: 'Unauthorized' }, 401);
  }

  const body = await request.json() as { taskId: string; result: ToolTaskResult };
  const raw = await env.STORMFORGE_KV.get(`task:${body.taskId}`);
  if (!raw) return json({ error: 'Task not found' }, 404);

  const task = JSON.parse(raw) as ToolTask;
  task.status = body.result.exitCode === 0 ? 'done' : 'error';
  task.result = body.result;
  await env.STORMFORGE_KV.put(`task:${body.taskId}`, JSON.stringify(task));

  let followUpsDispatched = 0;
  let promoted = 0;
  let bountyDrafts = 0;

  if (body.result.findings?.length > 0) {
    const store = new FindingsStore(env.STORMFORGE_KV);
    const existing = await store.getAll(task.scope.program);
    const toUpsert: Finding[] = [];

    for (const rawFinding of body.result.findings) {
      const toolFinding = enrichFinding({
        ...rawFinding,
        source: rawFinding.source ?? task.tool,
      });
      const target = findPromotionTarget(existing, toolFinding);
      if (target && /sqlmap|nuclei/i.test(task.tool)) {
        const upgraded = promoteWithToolConfirmation(target, toolFinding);
        await store.put(task.scope.program, upgraded);
        promoted++;
        // Also keep the tool finding for audit trail.
        toUpsert.push(toolFinding);
      } else {
        toUpsert.push(toolFinding);
      }
    }

    if (toUpsert.length) await store.upsertMany(task.scope.program, toUpsert);

    followUpsDispatched = await dispatchFollowUpsFromFindings(env, body.result.findings, task.scope, {
      scanId: task.scanId,
      maxTasks: 8,
    });

    // Re-draft bounty packs when tool confirmation unlocks submit-ready findings.
    const all = await store.getAll(task.scope.program);
    if (shouldAutoDraft(all)) {
      const pack = draftBountyAutomation(all, task.scope);
      bountyDrafts = pack.count;
      if (pack.count > 0) {
        await env.STORMFORGE_KV.put(
          `bounty:${task.scope.program}:latest`,
          JSON.stringify({
            program: task.scope.program,
            scanId: task.scanId,
            platform: pack.platform,
            createdAt: new Date().toISOString(),
            count: pack.count,
            packets: pack.packets,
            combinedMarkdown: pack.combinedMarkdown,
            trigger: `executor:${task.tool}`,
          }),
          { expirationTtl: 7776000 },
        );
      }
    }
  }

  // Also chain from tool stdout hosts even without structured findings (subfinder/katana).
  if (followUpsDispatched === 0 && body.result.stdout) {
    const synthetic = findingsFromToolStdout(task, body.result.stdout);
    if (synthetic.length) {
      followUpsDispatched = await dispatchFollowUpsFromFindings(env, synthetic, task.scope, {
        scanId: task.scanId,
        maxTasks: 5,
      });
    }
  }

  return json({
    status: task.status,
    findingsCount: body.result.findings?.length || 0,
    followUpsDispatched,
    promoted,
    bountyDrafts,
  });
}

/** Lightweight synthetic findings from recon tool stdout to seed the autonomy loop. */
function findingsFromToolStdout(
  task: ToolTask,
  stdout: string,
): Array<{ checkId: string; severity: string; target: string; title: string; evidence?: string }> {
  const out: Array<{ checkId: string; severity: string; target: string; title: string; evidence?: string }> = [];
  if (task.tool === 'subfinder' || task.tool === 'httpx') {
    for (const line of stdout.split('\n')) {
      const host = line.trim().replace(/^https?:\/\//, '').split(/[\s/]/)[0];
      if (host && host.includes('.')) {
        out.push({
          checkId: `recon-${task.tool}`,
          severity: 'info',
          target: `https://${host}`,
          title: `${task.tool} discovered ${host}`,
          evidence: line.slice(0, 200),
        });
      }
      if (out.length >= 10) break;
    }
  }
  if (task.tool === 'katana' || task.tool === 'ffuf') {
    for (const line of stdout.split('\n')) {
      const m = line.match(/https?:\/\/[^\s"'<>]+/);
      if (m && /[?&]\w+=/.test(m[0])) {
        out.push({
          checkId: `recon-${task.tool}`,
          severity: 'info',
          target: m[0],
          title: `Parameterized URL from ${task.tool}`,
          evidence: line.slice(0, 200),
        });
      }
      if (out.length >= 10) break;
    }
  }
  return out;
}

async function handleTaskStatus(scanId: string, env: Env): Promise<Response> {
  // List all tasks for a scan (scan through KV — not ideal but functional)
  const list = await env.STORMFORGE_KV.list({ prefix: 'task:' });
  const tasks: ToolTask[] = [];
  for (const key of list.keys) {
    const raw = await env.STORMFORGE_KV.get(key.name);
    if (raw) {
      const task = JSON.parse(raw) as ToolTask;
      if (task.scanId === scanId) tasks.push(task);
    }
  }
  return json({ scanId, tasks, total: tasks.length });
}

async function handlePlanAttack(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as { scope: Scope; targets: string[] };

  if (!body.scope?.authorized) {
    return json({ error: 'Scope not authorized. Set authorized: true.' }, 403);
  }

  const { refused } = partitionByScope(body.targets, body.scope);
  if (refused.length > 0) {
    return json({ error: 'Targets out of scope', refused }, 403);
  }

  // Use the vuln planner to generate tasks
  const plan = await planAttackSurface(body.targets, body.scope, env);

  // Dispatch all planned tasks
  const taskIds: string[] = [];
  const scanId = crypto.randomUUID();
  for (const planned of plan.tasks) {
    const task: ToolTask = {
      id: crypto.randomUUID(),
      scanId,
      tool: planned.tool,
      target: planned.target,
      args: planned.args,
      scope: body.scope,
      status: 'pending',
      timeoutSec: planned.timeoutSec || 300,
      createdAt: new Date().toISOString(),
    };
    await env.STORMFORGE_KV.put(`task:${task.id}`, JSON.stringify(task));
    taskIds.push(task.id);
  }

  // Add all to pending queue
  const queue = await getQueue(env);
  queue.push(...taskIds);
  await env.STORMFORGE_KV.put('task_queue:pending', JSON.stringify(queue));

  return json({
    scanId,
    tasksDispatched: taskIds.length,
    plan: plan.rationale,
    tasks: plan.tasks.map((t, i) => ({ id: taskIds[i], tool: t.tool, target: t.target })),
  });
}

// ─── Existing Scan Handlers ──────────────────────────────────────────────────

async function handleStartScan(request: Request, env: Env): Promise<Response> {
  let req: ScanRequest;
  try {
    req = (await request.json()) as ScanRequest;
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  // Inject Worker origin for blind SSRF OAST when the client did not supply one.
  if (!req.canaryBaseUrl) {
    try {
      req.canaryBaseUrl = new URL(request.url).origin;
    } catch {
      /* leave unset */
    }
  }

  const validationError = validateScanRequest(req);
  if (validationError) return json({ error: validationError }, 400);

  const { refused } = partitionByScope(req.targets, req.scope);
  if (refused.length > 0) {
    return json({ error: 'One or more targets are out of scope', refused }, 403);
  }

  const scanId = crypto.randomUUID();
  const id = env.SCAN_ORCHESTRATOR.idFromName(scanId);
  const stub = env.SCAN_ORCHESTRATOR.get(id);
  const res = await stub.fetch('https://do/start', {
    method: 'POST',
    body: JSON.stringify(req),
    headers: { 'content-type': 'application/json' },
  });
  if (!res.ok) return new Response(await res.text(), { status: res.status });
  return json({ scanId, status: 'running' });
}

async function handleCanaryHit(token: string, request: Request, env: Env): Promise<Response> {
  if (!isCanaryToken(token)) return json({ error: 'Invalid canary token' }, 400);
  await recordCanaryHit(env.STORMFORGE_KV, token, {
    hitAt: new Date().toISOString(),
    method: request.method,
    userAgent: request.headers.get('user-agent') ?? '',
    cfConnectingIp: request.headers.get('cf-connecting-ip') ?? undefined,
    path: new URL(request.url).pathname,
  });
  // Tiny body so fetchers / SSRF sinks that require 200 + content still "succeed".
  if (request.method === 'HEAD') {
    return new Response(null, {
      status: 200,
      headers: { 'cache-control': 'no-store', 'x-stormforge-canary': 'hit' },
    });
  }
  return new Response('ok', {
    status: 200,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-stormforge-canary': 'hit',
    },
  });
}

async function handleStatus(scanId: string, env: Env): Promise<Response> {
  const id = env.SCAN_ORCHESTRATOR.idFromName(scanId);
  const stub = env.SCAN_ORCHESTRATOR.get(id);
  const res = await stub.fetch('https://do/status');
  return new Response(await res.text(), {
    status: res.status,
    headers: { 'content-type': 'application/json' },
  });
}

async function handleReport(program: string, env: Env): Promise<Response> {
  const store = new FindingsStore(env.STORMFORGE_KV);
  const findings = await store.getAll(program);
  if (findings.length === 0) return json({ error: 'No findings for program' }, 404);

  const scope: Scope = {
    program,
    platform: 'generic',
    inScope: [],
    outOfScope: [],
    authorized: true,
  };
  const markdown = draftDisclosure(findings, scope);
  return new Response(markdown, { headers: { 'content-type': 'text/markdown; charset=utf-8' } });
}

async function handleListDrafts(program: string, env: Env): Promise<Response> {
  const list = await env.STORMFORGE_KV.list({ prefix: `draft:${program}:` });
  const drafts = [];
  for (const key of list.keys.slice(0, 50)) {
    const raw = await env.STORMFORGE_KV.get(key.name);
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw) as {
        scanId: string;
        program: string;
        createdAt: string;
        findingCount: number;
        markdown: string;
        bounty?: unknown;
      };
      drafts.push({
        key: key.name,
        scanId: parsed.scanId,
        createdAt: parsed.createdAt,
        findingCount: parsed.findingCount,
        markdownPreview: parsed.markdown.slice(0, 400),
        hasBountyPacks: Boolean(parsed.bounty),
      });
    } catch {
      /* skip bad draft */
    }
  }
  return json({ program, drafts, total: drafts.length });
}

async function handleBountyPacks(program: string, url: URL, env: Env): Promise<Response> {
  const store = new FindingsStore(env.STORMFORGE_KV);
  const findings = await store.getAll(program);
  if (!findings.length) return json({ error: 'No findings for program' }, 404);

  const platformParam = url.searchParams.get('platform');
  const platform: BountyPlatform | undefined =
    platformParam === 'immunefi' || platformParam === 'hackerone' ? platformParam : undefined;

  const scope: Scope = {
    program,
    platform: platform ?? 'hackerone',
    inScope: [],
    outOfScope: [],
    authorized: true,
  };
  const pack = draftBountyAutomation(findings, scope, platform);
  const ranked = sortByCvss(findings).map((f) => {
    const cvss = estimateCvss(f);
    return {
      id: f.id,
      checkId: f.checkId,
      title: f.title,
      severity: f.severity,
      target: f.target,
      cvssScore: cvss.score,
      cvssVector: cvss.vector,
      cvssRating: cvss.rating,
    };
  });

  // Persist latest bounty automation snapshot for the dashboard.
  await env.STORMFORGE_KV.put(
    `bounty:${program}:latest`,
    JSON.stringify({
      program,
      platform: pack.platform,
      createdAt: new Date().toISOString(),
      count: pack.count,
      packets: pack.packets,
      combinedMarkdown: pack.combinedMarkdown,
    }),
    { expirationTtl: 7776000 },
  );

  return json({
    program,
    platform: pack.platform,
    bountyDrafts: pack.count,
    packets: pack.packets,
    rankedByCvss: ranked,
    combinedMarkdown: pack.combinedMarkdown,
  });
}

async function handleBountyGenerate(request: Request, env: Env): Promise<Response> {
  const body = (await request.json()) as {
    program: string;
    platform?: BountyPlatform;
    scope?: Scope;
    findings?: import('./types.js').Finding[];
  };
  if (!body.program) return json({ error: 'program required' }, 400);

  const scope: Scope =
    body.scope ??
    ({
      program: body.program,
      platform: body.platform === 'immunefi' ? 'immunefi' : 'hackerone',
      inScope: [],
      outOfScope: [],
      authorized: true,
    } satisfies Scope);

  let findings = body.findings;
  if (!findings?.length) {
    const store = new FindingsStore(env.STORMFORGE_KV);
    findings = await store.getAll(body.program);
  }
  if (!findings?.length) return json({ error: 'No findings to draft' }, 404);

  const pack = draftBountyAutomation(findings, scope, body.platform);
  await env.STORMFORGE_KV.put(
    `bounty:${body.program}:latest`,
    JSON.stringify({
      program: body.program,
      platform: pack.platform,
      createdAt: new Date().toISOString(),
      count: pack.count,
      packets: pack.packets,
      combinedMarkdown: pack.combinedMarkdown,
    }),
    { expirationTtl: 7776000 },
  );

  return json({
    status: 'drafted',
    platform: pack.platform,
    bountyDrafts: pack.count,
    packets: pack.packets,
    note: 'Never auto-submitted. Copy markdown/fields into the platform UI after review.',
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function getQueue(env: Env): Promise<string[]> {
  const raw = await env.STORMFORGE_KV.get('task_queue:pending');
  return raw ? JSON.parse(raw) : [];
}

function validateScanRequest(req: ScanRequest): string | null {
  if (!req || typeof req !== 'object') return 'Missing request body';
  if (!req.scope) return 'Missing scope';
  if (!req.scope.authorized) return 'Scope is not marked authorized. Confirm you have permission to test these assets.';
  if (!Array.isArray(req.scope.inScope) || req.scope.inScope.length === 0) return 'scope.inScope must list at least one authorized host';
  if (!Array.isArray(req.targets) || req.targets.length === 0) return 'targets must be a non-empty array';
  if (req.targets.length > 50) return 'Too many seed targets (max 50). Split into multiple scans.';
  const sessionErr = validateSession(req.session);
  if (sessionErr) return sessionErr;
  if (req.canaryBaseUrl !== undefined) {
    if (typeof req.canaryBaseUrl !== 'string') return 'canaryBaseUrl must be a string';
    try {
      const u = new URL(req.canaryBaseUrl);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') {
        return 'canaryBaseUrl must be http(s)';
      }
    } catch {
      return 'canaryBaseUrl must be a valid URL';
    }
  }
  return null;
}

function isSeverity(v: string | null): v is Severity {
  return v === 'info' || v === 'low' || v === 'medium' || v === 'high' || v === 'critical';
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

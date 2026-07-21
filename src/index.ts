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
import { draftDisclosure } from './report/drafter.js';
import { listChecks } from './detect/registry.js';
import { DASHBOARD_HTML } from './dashboard-html.js';
import { planAttackSurface } from './planning/vuln-planner.js';
import { dispatchFollowUpsFromFindings } from './planning/dispatch-followups.js';

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

  // Persist any findings from the executor and close the autonomy loop.
  let followUpsDispatched = 0;
  if (body.result.findings?.length > 0) {
    const store = new FindingsStore(env.STORMFORGE_KV);
    await store.upsertMany(task.scope.program, body.result.findings);
    followUpsDispatched = await dispatchFollowUpsFromFindings(
      env,
      body.result.findings,
      task.scope,
      { scanId: task.scanId, maxTasks: 8 },
    );
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
      };
      drafts.push({
        key: key.name,
        scanId: parsed.scanId,
        createdAt: parsed.createdAt,
        findingCount: parsed.findingCount,
        markdownPreview: parsed.markdown.slice(0, 400),
      });
    } catch {
      /* skip bad draft */
    }
  }
  return json({ program, drafts, total: drafts.length });
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

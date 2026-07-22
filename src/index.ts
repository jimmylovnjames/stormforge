// StormForge C2 — Cloudflare Worker entry point.
//
// Command & Control brain: dashboard, passive scans, task queue for remote
// executor, LLM-driven vuln planning. Never runs offensive tools itself.
// Fail-closed auth when EXECUTOR_SECRET is configured (required in prod).

import type { Env, Finding, ScanRequest, Scope, ToolTask, ToolTaskResult, ToolName, Severity } from './types.js';
import { ScanOrchestrator } from './do/scan-orchestrator.js';
import { partitionByScope, assertInScope, evaluateScope } from './scope/scope-guard.js';
import { FindingsStore } from './findings/store.js';
import { draftDisclosure } from './report/drafter.js';
import { prioritizeFindings, draftTriageReport } from './findings/prioritize.js';
import { OastStore } from './oast/store.js';
import { pollAndCorrelate } from './oast/poller.js';
import { oastConfigured, parseCollaborator } from './oast/collaborator.js';
import { listChecks } from './detect/registry.js';
import { DASHBOARD_HTML } from './dashboard-html.js';
import { planAttackSurface } from './planning/vuln-planner.js';
import { auditLog, listAuditEvents } from './audit/log.js';
import { enqueueTasks, leaseBatch } from './tasks/queue.js';
import { processTaskCompletion } from './tasks/complete-followup.js';
import { handleOrchestrateMessage } from './orchestrate/handler.js';
import { buildGrokInstructions } from './orchestrate/commands.js';
import { MOBILE_HTML } from './orchestrate/mobile-html.js';
import { buildOpenApi } from './orchestrate/openapi.js';

export { ScanOrchestrator };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    try {
      if (request.method === 'GET' && pathname === '/') {
        return new Response(DASHBOARD_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
      }

      if (request.method === 'GET' && pathname === '/m') {
        return new Response(MOBILE_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
      }

      if (request.method === 'GET' && pathname === '/openapi.json') {
        return json(buildOpenApi(url.origin));
      }

      if (request.method === 'GET' && pathname === '/api/grok/instructions') {
        return new Response(buildGrokInstructions(url.origin), {
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      }

      if (request.method === 'POST' && pathname === '/api/orchestrate') {
        return await handleOrchestrate(request, env, url.origin);
      }

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
        const findings = await store.getAll(decodeURIComponent(findingsMatch[1]));
        return json({ findings });
      }

      const reportMatch = pathname.match(/^\/api\/report\/([^/]+)$/);
      if (request.method === 'GET' && reportMatch) {
        return await handleReport(decodeURIComponent(reportMatch[1]), env, request);
      }

      const triageMatch = pathname.match(/^\/api\/triage\/([^/]+)$/);
      if (request.method === 'GET' && triageMatch) {
        return await handleTriage(decodeURIComponent(triageMatch[1]), env, request);
      }

      if (request.method === 'GET' && pathname === '/api/oast/status') {
        return await handleOastStatus(env);
      }

      if (request.method === 'POST' && pathname === '/api/oast/poll') {
        return await handleOastPoll(request, env);
      }

      const oastResultsMatch = pathname.match(/^\/api\/oast\/results\/([^/]+)$/);
      if (request.method === 'GET' && oastResultsMatch) {
        return await handleOastResults(decodeURIComponent(oastResultsMatch[1]), env);
      }

      if (request.method === 'GET' && pathname === '/api/checks') {
        return json({ checks: listChecks().map((c) => ({ id: c.id, title: c.title, cwe: c.cwe })) });
      }

      if (request.method === 'GET' && pathname === '/api/audit') {
        if (!authenticateOperator(request, env)) {
          await auditLog(env, { action: 'auth.failed', detail: 'audit list unauthorized' });
          return json({ error: 'Unauthorized' }, 401);
        }
        const events = await listAuditEvents(env, 100);
        return json({ events });
      }

      if (request.method === 'POST' && pathname === '/api/tasks/dispatch') {
        return await handleDispatch(request, env);
      }

      if (request.method === 'GET' && pathname === '/api/tasks/poll') {
        return await handlePoll(request, env);
      }

      if (request.method === 'POST' && pathname === '/api/tasks/complete') {
        return await handleComplete(request, env);
      }

      const taskStatusMatch = pathname.match(/^\/api\/tasks\/status\/([^/]+)$/);
      if (request.method === 'GET' && taskStatusMatch) {
        return await handleTaskStatus(taskStatusMatch[1], env);
      }

      if (request.method === 'POST' && pathname === '/api/plan-attack') {
        return await handlePlanAttack(request, env);
      }

      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: (e as Error).message }, 500);
    }
  },
};

/** Fail-closed: require EXECUTOR_SECRET unless ALLOW_INSECURE_EXECUTOR=true. */
export function authenticateExecutor(request: Request, env: Env): boolean {
  const secret = env.EXECUTOR_SECRET;
  if (!secret) {
    return env.ALLOW_INSECURE_EXECUTOR === 'true';
  }
  const header = request.headers.get('x-executor-secret') || '';
  return header === secret;
}

/** Operator actions (plan/dispatch/audit/orchestrate) use the same shared secret. */
function authenticateOperator(request: Request, env: Env): boolean {
  return authenticateExecutor(request, env);
}

async function handleOrchestrate(request: Request, env: Env, baseUrl: string): Promise<Response> {
  if (!authenticateOperator(request, env)) {
    await auditLog(env, { action: 'auth.failed', detail: 'orchestrate unauthorized' });
    return json(
      {
        ok: false,
        error: 'Unauthorized — set x-executor-secret',
        text: 'Unauthorized — paste your EXECUTOR_SECRET as header x-executor-secret (or into /m).',
      },
      401,
    );
  }

  let body: { message?: string };
  try {
    body = (await request.json()) as { message?: string };
  } catch {
    return json({ ok: false, error: 'Invalid JSON body', text: 'Invalid JSON body' }, 400);
  }

  const message = typeof body.message === 'string' ? body.message : '';
  if (!message.trim()) {
    return json(
      { ok: false, error: 'Missing message. Try {"message":"help"}', text: 'Missing message. Try help' },
      400,
    );
  }

  const result = await handleOrchestrateMessage(env, message, {
    baseUrl,
    actor: 'grok-mobile',
  });
  return json(
    { ok: result.ok, text: result.text, data: result.data },
    result.ok ? 200 : result.status || 400,
  );
}

async function handleDispatch(request: Request, env: Env): Promise<Response> {
  if (!authenticateOperator(request, env)) {
    await auditLog(env, { action: 'auth.failed', detail: 'dispatch unauthorized' });
    return json({ error: 'Unauthorized — set EXECUTOR_SECRET (or ALLOW_INSECURE_EXECUTOR=true for local only)' }, 401);
  }

  const body = (await request.json()) as {
    scanId: string;
    tool: ToolName;
    target: string;
    args?: Record<string, string>;
    scope: Scope;
    timeoutSec?: number;
  };

  if (!body.scope?.authorized) {
    await auditLog(env, {
      action: 'task.refused',
      detail: 'Scope not authorized',
      target: body.target,
      program: body.scope?.program,
    });
    return json({ error: 'Scope not authorized' }, 403);
  }

  const decision = evaluateScope(body.target, body.scope);
  if (!decision.allowed) {
    await auditLog(env, {
      action: 'scope.refused',
      detail: decision.reason,
      target: body.target,
      program: body.scope.program,
    });
    return json({ error: `Target out of scope: ${decision.reason}` }, 403);
  }

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
    followUpDepth: 0,
  };

  await enqueueTasks(env, [task]);

  await auditLog(env, {
    action: 'task.dispatch',
    detail: `${task.tool} → ${task.target}`,
    target: task.target,
    program: task.scope.program,
    meta: { taskId: task.id, tool: task.tool },
  });

  return json({ taskId: task.id, status: 'pending' });
}

async function handlePoll(request: Request, env: Env): Promise<Response> {
  if (!authenticateExecutor(request, env)) {
    await auditLog(env, { action: 'auth.failed', detail: 'poll unauthorized' });
    return json({ error: 'Unauthorized' }, 401);
  }

  const tasks = await leaseBatch(env, { limit: 5 });

  await auditLog(env, {
    action: 'task.poll',
    detail: `Dispensed ${tasks.length} task(s)`,
    meta: { count: tasks.length },
  });

  return json({ tasks });
}

async function handleComplete(request: Request, env: Env): Promise<Response> {
  if (!authenticateExecutor(request, env)) {
    await auditLog(env, { action: 'auth.failed', detail: 'complete unauthorized' });
    return json({ error: 'Unauthorized' }, 401);
  }

  const body = (await request.json()) as { taskId: string; result: ToolTaskResult };
  const exists = await env.STORMFORGE_KV.get(`task:${body.taskId}`);
  if (!exists) return json({ error: 'Task not found' }, 404);

  const out = await processTaskCompletion(env, body);
  return json({
    status: out.status,
    findingsCount: out.findingsStored,
    followUpsEnqueued: out.followUpsEnqueued,
  });
}

async function handleTaskStatus(scanId: string, env: Env): Promise<Response> {
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
  if (!authenticateOperator(request, env)) {
    await auditLog(env, { action: 'auth.failed', detail: 'plan-attack unauthorized' });
    return json({ error: 'Unauthorized — set x-executor-secret' }, 401);
  }

  const body = (await request.json()) as {
    scope: Scope;
    targets: string[];
    findings?: { checkId: string; severity: string; target: string; title?: string; evidence?: string }[];
  };

  if (!body.scope?.authorized) {
    await auditLog(env, {
      action: 'plan.attack',
      detail: 'REFUSED unauthorized scope',
      program: body.scope?.program,
    });
    return json({ error: 'Scope not authorized. Set authorized: true.' }, 403);
  }

  const { allowed, refused } = partitionByScope(body.targets, body.scope);
  if (refused.length > 0) {
    await auditLog(env, {
      action: 'scope.refused',
      detail: `${refused.length} target(s) out of scope`,
      program: body.scope.program,
      meta: { refused: refused.length },
    });
    return json({ error: 'Targets out of scope', refused }, 403);
  }

  const priorFindings: Finding[] = (body.findings || []).map((f) => ({
    id: 'prior',
    checkId: f.checkId,
    title: f.title || f.checkId,
    severity: (['info', 'low', 'medium', 'high', 'critical'].includes(f.severity)
      ? f.severity
      : 'info') as Severity,
    target: f.target,
    description: '',
    evidence: f.evidence || '',
    reproduction: [],
    remediation: '',
    references: [],
    needsManualReview: true,
    discoveredAt: new Date().toISOString(),
  }));

  const scanId = crypto.randomUUID();

  // Explicit plan-attack always dispatches (operator-initiated), independent of SCAN_MODE.
  const plan = await planAttackSurface(allowed, body.scope, env, { findings: priorFindings });
  if (!plan.tasks.length) {
    await auditLog(env, {
      action: 'plan.attack',
      detail: `No tasks: ${plan.rationale}`,
      program: body.scope.program,
    });
    return json({ error: 'No tasks planned', rationale: plan.rationale }, 400);
  }

  const tasks: ToolTask[] = plan.tasks.map((planned) => ({
    id: crypto.randomUUID(),
    scanId,
    tool: planned.tool,
    target: planned.target,
    args: planned.args,
    scope: body.scope,
    status: 'pending' as const,
    timeoutSec: planned.timeoutSec || 300,
    createdAt: new Date().toISOString(),
    followUpDepth: 0,
  }));
  await enqueueTasks(env, tasks);

  await auditLog(env, {
    action: 'plan.attack',
    detail: `Dispatched ${tasks.length} tasks (${plan.source})`,
    program: body.scope.program,
    meta: { scanId, source: plan.source, count: tasks.length },
  });

  return json({
    scanId,
    tasksDispatched: tasks.length,
    plan: plan.rationale,
    source: plan.source,
    tasks: plan.tasks.map((t, i) => ({
      id: tasks[i]!.id,
      tool: t.tool,
      target: t.target,
      rationale: t.rationale,
    })),
  });
}

async function handleStartScan(request: Request, env: Env): Promise<Response> {
  let req: ScanRequest;
  try {
    req = (await request.json()) as ScanRequest;
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const validationError = validateScanRequest(req);
  if (validationError) {
    await auditLog(env, { action: 'scan.refused', detail: validationError, program: req?.scope?.program });
    return json({ error: validationError }, 400);
  }

  const { refused } = partitionByScope(req.targets, req.scope);
  if (refused.length > 0) {
    await auditLog(env, {
      action: 'scope.refused',
      detail: 'scan targets out of scope',
      program: req.scope.program,
      meta: { refused: refused.length },
    });
    return json({ error: 'One or more targets are out of scope', refused }, 403);
  }

  const scanId = crypto.randomUUID();
  const id = env.SCAN_ORCHESTRATOR.idFromName(scanId);
  const stub = env.SCAN_ORCHESTRATOR.get(id);
  const res = await stub.fetch('https://do/start', {
    method: 'POST',
    body: JSON.stringify({ ...req, scanId }),
    headers: { 'content-type': 'application/json' },
  });
  if (!res.ok) return new Response(await res.text(), { status: res.status });

  await auditLog(env, {
    action: 'scan.started',
    detail: `Passive scan ${scanId}`,
    program: req.scope.program,
    meta: { scanId, targets: req.targets.length },
  });

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

async function handleReport(program: string, env: Env, request: Request): Promise<Response> {
  const store = new FindingsStore(env.STORMFORGE_KV);
  const findings = await store.getAll(program);
  if (findings.length === 0) return json({ error: 'No findings for program' }, 404);

  const url = new URL(request.url);
  const submitReadyOnly = url.searchParams.get('submitReady') === '1' || url.searchParams.get('ready') === '1';
  const minSeverity = (url.searchParams.get('minSeverity') as Finding['severity'] | null) || undefined;

  const scope: Scope = {
    program,
    platform: 'generic',
    inScope: [],
    outOfScope: [],
    authorized: true,
  };
  const markdown = draftDisclosure(findings, scope, { submitReadyOnly, minSeverity });
  return new Response(markdown, { headers: { 'content-type': 'text/markdown; charset=utf-8' } });
}

async function handleOastStatus(env: Env): Promise<Response> {
  const cfg = parseCollaborator(env);
  const store = new OastStore(env.STORMFORGE_KV);
  const tokens = await store.allTokens();
  const lastPoll = await store.getLastPoll();
  return json({
    configured: oastConfigured(env),
    callbackDomain: cfg?.callbackDomain ?? null,
    payloadsTracked: tokens.length,
    lastPollAt: lastPoll ? new Date(lastPoll).toISOString() : null,
  });
}

async function handleOastPoll(request: Request, env: Env): Promise<Response> {
  if (!authenticateOperator(request, env)) {
    await auditLog(env, { action: 'auth.failed', detail: 'oast poll unauthorized' });
    return json({ error: 'Unauthorized — set x-executor-secret' }, 401);
  }
  const summary = await pollAndCorrelate(env);
  return json(summary, summary.configured ? 200 : 400);
}

async function handleOastResults(program: string, env: Env): Promise<Response> {
  const store = new OastStore(env.STORMFORGE_KV);
  const results = await store.results(env, program);
  return json({ program, ...results });
}

async function handleTriage(program: string, env: Env, request: Request): Promise<Response> {
  const store = new FindingsStore(env.STORMFORGE_KV);
  const findings = await store.getAll(program);
  if (findings.length === 0) return json({ error: 'No findings for program' }, 404);

  const url = new URL(request.url);
  const readyOnly = url.searchParams.get('ready') === '1' || url.searchParams.get('submitReady') === '1';
  const limitRaw = Number(url.searchParams.get('limit'));
  const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(500, Math.floor(limitRaw)) : undefined;

  const result = prioritizeFindings(findings);
  let entries = readyOnly ? result.entries.filter((e) => e.submitReady) : result.entries;
  if (limit) entries = entries.slice(0, limit);
  const view = { total: result.total, submitReady: result.submitReady, entries };

  if (url.searchParams.get('format') === 'md') {
    const md = draftTriageReport({ ...result, entries }, program);
    return new Response(md, { headers: { 'content-type': 'text/markdown; charset=utf-8' } });
  }
  return json({ program, ...view });
}

function validateScanRequest(req: ScanRequest): string | null {
  if (!req || typeof req !== 'object') return 'Missing request body';
  if (!req.scope) return 'Missing scope';
  if (!req.scope.authorized) return 'Scope is not marked authorized. Confirm you have permission to test these assets.';
  if (!Array.isArray(req.scope.inScope) || req.scope.inScope.length === 0)
    return 'scope.inScope must list at least one authorized host';
  if (!Array.isArray(req.targets) || req.targets.length === 0) return 'targets must be a non-empty array';
  if (req.targets.length > 50) return 'Too many seed targets (max 50). Split into multiple scans.';
  return null;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

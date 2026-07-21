// Execute parsed Grok / mobile orchestrate commands against C2 APIs.
// AUTHORIZED TARGETS ONLY — never implies authorization.

import type { Env, Finding, Scope, ToolName, ToolTask } from '../types.js';
import { parseOrchestrateMessage, helpText, type ParsedCommand } from './commands.js';
import { partitionByScope, evaluateScope, assertInScope } from '../scope/scope-guard.js';
import { FindingsStore } from '../findings/store.js';
import { draftDisclosure } from '../report/drafter.js';
import { planAttackSurface } from '../planning/vuln-planner.js';
import { auditLog, listAuditEvents } from '../audit/log.js';
import { enqueueTasks } from '../tasks/queue.js';

export interface OrchestrateResult {
  ok: boolean;
  text: string;
  data?: unknown;
  status?: number;
}

function scopeFromCmd(cmd: ParsedCommand): Scope {
  return {
    program: cmd.program || 'mobile-lab',
    platform: cmd.platform || 'generic',
    inScope: cmd.inScope || [],
    outOfScope: cmd.outOfScope || [],
    authorized: !!cmd.authorized,
    notes: 'Orchestrated via Grok / mobile',
  };
}

export async function handleOrchestrateMessage(
  env: Env,
  rawMessage: string,
  opts: { baseUrl?: string; actor?: string } = {},
): Promise<OrchestrateResult> {
  const cmd = parseOrchestrateMessage(rawMessage);
  return handleParsedCommand(env, cmd, opts);
}

export async function handleParsedCommand(
  env: Env,
  cmd: ParsedCommand,
  opts: { baseUrl?: string; actor?: string } = {},
): Promise<OrchestrateResult> {
  const actor = opts.actor ?? 'grok';
  const baseUrl = opts.baseUrl;

  if (cmd.error && (cmd.intent === 'help' || !cmd.authorized)) {
    if (cmd.intent === 'help') {
      return {
        ok: true,
        text: [cmd.error, helpText(baseUrl), cmd.replyHint].filter(Boolean).join('\n\n'),
      };
    }
    return { ok: false, text: cmd.error, status: 400 };
  }

  switch (cmd.intent) {
    case 'help':
      return { ok: true, text: helpText(baseUrl) };

    case 'audit': {
      const events = await listAuditEvents(env, 30);
      const text =
        events.length === 0
          ? 'No audit entries yet.'
          : events
              .map((e) => `• ${e.at} ${e.action}${e.detail ? ` — ${e.detail}` : ''}`)
              .join('\n');
      return { ok: true, text, data: { events } };
    }

    case 'findings': {
      if (cmd.error) return { ok: false, text: cmd.error, status: 400 };
      const program = cmd.program!;
      const store = new FindingsStore(env.STORMFORGE_KV);
      const findings = await store.getAll(program);
      if (findings.length === 0) {
        return { ok: true, text: `No findings for program ${program}.`, data: { findings: [] } };
      }
      const text = findings
        .slice(0, 20)
        .map(
          (f) =>
            `• [${f.severity}] ${f.title}${f.confidence != null ? ` conf=${f.confidence.toFixed(2)}` : ''}`,
        )
        .join('\n');
      return {
        ok: true,
        text: `Findings for ${program} (${findings.length}):\n${text}`,
        data: { findings: findings.slice(0, 20) },
      };
    }

    case 'report': {
      if (cmd.error) return { ok: false, text: cmd.error, status: 400 };
      const program = cmd.program!;
      const store = new FindingsStore(env.STORMFORGE_KV);
      const findings = await store.getAll(program);
      if (findings.length === 0) {
        return { ok: false, text: `No findings for program ${program}.`, status: 404 };
      }
      const scope: Scope = {
        program,
        platform: 'generic',
        inScope: [],
        outOfScope: [],
        authorized: true,
      };
      const md = draftDisclosure(findings, scope);
      const text = md.length > 3500 ? `${md.slice(0, 3500)}\n…(truncated)` : md;
      return { ok: true, text, data: { markdown: md } };
    }

    case 'status': {
      if (cmd.error || !cmd.scanId) {
        return { ok: false, text: cmd.error || 'Usage: status <scanId>', status: 400 };
      }
      const id = env.SCAN_ORCHESTRATOR.idFromName(cmd.scanId);
      const stub = env.SCAN_ORCHESTRATOR.get(id);
      const res = await stub.fetch('https://do/status');
      const body = (await res.json()) as Record<string, unknown>;
      const text = [
        `Scan ${cmd.scanId}`,
        `HTTP ${res.status}`,
        typeof body.status === 'string' ? `status=${body.status}` : '',
        body.findingsCount != null ? `findings=${body.findingsCount}` : '',
        JSON.stringify(body).slice(0, 800),
      ]
        .filter(Boolean)
        .join('\n');
      return { ok: res.ok, text, data: body, status: res.ok ? 200 : res.status };
    }

    case 'tasks': {
      if (cmd.error || !cmd.scanId) {
        return { ok: false, text: cmd.error || 'Usage: tasks <scanId>', status: 400 };
      }
      const list = await env.STORMFORGE_KV.list({ prefix: 'task:' });
      const tasks: ToolTask[] = [];
      for (const key of list.keys) {
        const raw = await env.STORMFORGE_KV.get(key.name);
        if (!raw) continue;
        const task = JSON.parse(raw) as ToolTask;
        if (task.scanId === cmd.scanId) tasks.push(task);
      }
      if (tasks.length === 0) {
        return { ok: true, text: `No tasks for scan ${cmd.scanId}.`, data: { tasks: [] } };
      }
      const text = tasks
        .slice(0, 25)
        .map((t) => `• ${t.id.slice(0, 8)} ${t.tool} ${t.status} → ${t.target}`)
        .join('\n');
      return {
        ok: true,
        text: `Tasks for ${cmd.scanId} (${tasks.length}):\n${text}`,
        data: { tasks: tasks.slice(0, 25) },
      };
    }

    case 'dispatch':
      return dispatchTool(env, cmd, actor);

    case 'plan':
      return planAttack(env, cmd, actor);

    case 'scan':
      return startPassiveScan(env, cmd, actor);

    default: {
      const _exhaustive: never = cmd.intent;
      return { ok: false, text: `Unhandled intent: ${_exhaustive}`, status: 500 };
    }
  }
}

async function dispatchTool(
  env: Env,
  cmd: ParsedCommand,
  actor: string,
): Promise<OrchestrateResult> {
  if (cmd.error) return { ok: false, text: cmd.error, status: 400 };
  if (!cmd.authorized || !cmd.tool || !cmd.targets?.length) {
    return {
      ok: false,
      text: 'Usage: dispatch httpx https://target authorized program=lab inScope=target.com',
      status: 400,
    };
  }

  const scope = scopeFromCmd(cmd);
  if (!scope.inScope.length) {
    return { ok: false, text: 'Need inScope=… for dispatch.', status: 400 };
  }

  const target = cmd.targets[0]!;
  const decision = evaluateScope(target, scope);
  if (!decision.allowed) {
    await auditLog(env, {
      action: 'scope.refused',
      detail: decision.reason,
      target,
      program: scope.program,
      meta: { actor },
    });
    return { ok: false, text: `Target out of scope: ${decision.reason}`, status: 403 };
  }

  try {
    assertInScope(target, scope);
  } catch (e) {
    return { ok: false, text: `Target out of scope: ${(e as Error).message}`, status: 403 };
  }

  const scanId = crypto.randomUUID();
  const task: ToolTask = {
    id: crypto.randomUUID(),
    scanId,
    tool: cmd.tool as ToolName,
    target,
    args: {},
    scope,
    status: 'pending',
    timeoutSec: 300,
    createdAt: new Date().toISOString(),
    followUpDepth: 0,
  };
  await enqueueTasks(env, [task]);
  await auditLog(env, {
    action: 'task.dispatch',
    detail: `orchestrate ${task.tool} → ${task.target}`,
    target,
    program: scope.program,
    meta: { taskId: task.id, tool: task.tool, actor },
  });

  return {
    ok: true,
    text: `Queued ${cmd.tool} → task ${task.id}\nscanId=${scanId}\nEnsure the remote executor is polling. Next: tasks ${scanId}`,
    data: { scanId, taskId: task.id, tool: cmd.tool },
  };
}

async function planAttack(
  env: Env,
  cmd: ParsedCommand,
  actor: string,
): Promise<OrchestrateResult> {
  if (cmd.error) return { ok: false, text: cmd.error, status: 400 };
  if (!cmd.authorized || !cmd.targets?.length) {
    return {
      ok: false,
      text: 'Usage: plan https://target authorized program=lab inScope=target.com',
      status: 400,
    };
  }

  const scope = scopeFromCmd(cmd);
  if (!scope.inScope.length) {
    return { ok: false, text: 'Need inScope hosts (or wildcards) for plan.', status: 400 };
  }

  const { allowed, refused } = partitionByScope(cmd.targets, scope);
  if (refused.length > 0) {
    return {
      ok: false,
      text: `Targets out of scope: ${refused.join(', ')}`,
      status: 403,
      data: { refused },
    };
  }

  const scanId = crypto.randomUUID();
  const plan = await planAttackSurface(allowed, scope, env, { findings: [] as Finding[] });
  if (!plan.tasks.length) {
    await auditLog(env, {
      action: 'plan.attack',
      detail: `orchestrate no tasks: ${plan.rationale}`,
      program: scope.program,
      meta: { actor },
    });
    return { ok: false, text: `No tasks planned: ${plan.rationale}`, status: 400 };
  }

  const tasks: ToolTask[] = plan.tasks.map((planned) => ({
    id: crypto.randomUUID(),
    scanId,
    tool: planned.tool,
    target: planned.target,
    args: planned.args,
    scope,
    status: 'pending' as const,
    timeoutSec: planned.timeoutSec || 300,
    createdAt: new Date().toISOString(),
    followUpDepth: 0,
  }));
  await enqueueTasks(env, tasks);
  await auditLog(env, {
    action: 'plan.attack',
    detail: `orchestrate dispatched ${tasks.length} (${plan.source})`,
    program: scope.program,
    meta: { scanId, source: plan.source, count: tasks.length, actor },
  });

  const lines = plan.tasks
    .slice(0, 10)
    .map((t, i) => `• ${t.tool} → ${t.target} (${tasks[i]!.id.slice(0, 8)})`);
  return {
    ok: true,
    text: [
      `Plan ready → scanId=${scanId}`,
      `Dispatched ${tasks.length} remote task(s) (${plan.source})`,
      ...lines,
      `Next: ensure executor is running, then tasks ${scanId}`,
    ].join('\n'),
    data: {
      scanId,
      tasksDispatched: tasks.length,
      source: plan.source,
      rationale: plan.rationale,
    },
  };
}

async function startPassiveScan(
  env: Env,
  cmd: ParsedCommand,
  actor: string,
): Promise<OrchestrateResult> {
  if (cmd.error) return { ok: false, text: cmd.error, status: 400 };
  if (!cmd.authorized || !cmd.targets?.length) {
    return {
      ok: false,
      text: 'Usage: scan https://api.target.com *.target.com authorized program=lab',
      status: 400,
    };
  }

  const scope = scopeFromCmd(cmd);
  if (!scope.inScope.length) {
    return { ok: false, text: 'Need inScope hosts for scan.', status: 400 };
  }

  const { refused } = partitionByScope(cmd.targets, scope);
  if (refused.length > 0) {
    return {
      ok: false,
      text: `Targets out of scope: ${refused.join(', ')}`,
      status: 403,
      data: { refused },
    };
  }

  const scanId = crypto.randomUUID();
  const id = env.SCAN_ORCHESTRATOR.idFromName(scanId);
  const stub = env.SCAN_ORCHESTRATOR.get(id);
  const res = await stub.fetch('https://do/start', {
    method: 'POST',
    body: JSON.stringify({ scope, targets: cmd.targets }),
    headers: { 'content-type': 'application/json' },
  });
  if (!res.ok) {
    const errText = await res.text();
    return { ok: false, text: `Scan failed to start: ${errText}`, status: res.status };
  }

  await auditLog(env, {
    action: 'scan.started',
    detail: `orchestrate passive scan ${scanId}`,
    program: scope.program,
    meta: { scanId, targets: cmd.targets.length, actor },
  });

  return {
    ok: true,
    text: [
      `Passive scan started → scanId=${scanId}`,
      `Program: ${scope.program}`,
      `Targets: ${cmd.targets.join(', ')}`,
      `Next: status ${scanId} | findings ${scope.program}`,
    ].join('\n'),
    data: { scanId, status: 'running', program: scope.program },
  };
}

// Hybrid mode: after passive recon (or on demand), plan + enqueue executor tasks.

import type { Env, Finding, Scope, ToolTask } from '../types.js';
import { planAttackSurface, planFromFindings } from '../planning/vuln-planner.js';
import { evaluateScope, partitionByScope } from '../scope/scope-guard.js';
import { auditLog } from '../audit/log.js';
import { enqueueTasks, taskDedupKey } from './queue.js';

export function shouldHybridDispatch(env: Env, scope: Scope): boolean {
  return (env.SCAN_MODE || '').toLowerCase() === 'hybrid' && !!scope.authorized;
}

export interface HybridDispatchInput {
  scanId: string;
  scope: Scope;
  targets: string[];
  findings?: Finding[];
  /** Starting follow-up depth for enqueued tasks (default 0). */
  followUpDepth?: number;
  maxTasks?: number;
}

export interface HybridDispatchResult {
  enqueued: number;
  refused: number;
  dedupKeys: string[];
  source: string;
  rationale: string;
}

/**
 * Plan attack surface (finding-driven when available) and enqueue unique tasks.
 * No-op when SCAN_MODE !== hybrid or scope unauthorized.
 */
export async function dispatchHybridFollowUp(
  env: Env,
  input: HybridDispatchInput,
): Promise<HybridDispatchResult> {
  if (!shouldHybridDispatch(env, input.scope)) {
    return { enqueued: 0, refused: 0, dedupKeys: [], source: 'skipped', rationale: 'not hybrid or unauthorized' };
  }

  const { allowed, refused } = partitionByScope(input.targets, input.scope);
  if (!allowed.length) {
    await auditLog(env, {
      action: 'plan.attack',
      detail: 'hybrid dispatch refused — no in-scope targets',
      program: input.scope.program,
      meta: { scanId: input.scanId, refused: refused.length },
    });
    return {
      enqueued: 0,
      refused: refused.length,
      dedupKeys: [],
      source: 'skipped',
      rationale: 'no in-scope targets',
    };
  }

  const plan =
    input.findings?.length
      ? (() => {
          const evolved = planFromFindings(input.findings, input.scope);
          return evolved.tasks.length
            ? evolved
            : null;
        })()
      : null;

  const finalPlan =
    plan ??
    (await planAttackSurface(allowed, input.scope, env, { findings: input.findings }));

  const depth = input.followUpDepth ?? 0;
  const maxTasks = input.maxTasks ?? 12;
  const seen = new Set<string>();
  const tasks: ToolTask[] = [];
  const dedupKeys: string[] = [];

  for (const p of finalPlan.tasks) {
    if (tasks.length >= maxTasks) break;
    if (!evaluateScope(p.target, input.scope).allowed) continue;
    const key = taskDedupKey(p);
    if (seen.has(key)) continue;
    seen.add(key);
    dedupKeys.push(key);
    tasks.push({
      id: crypto.randomUUID(),
      scanId: input.scanId,
      tool: p.tool,
      target: p.target,
      args: p.args,
      scope: input.scope,
      status: 'pending',
      timeoutSec: p.timeoutSec || 300,
      createdAt: new Date().toISOString(),
      followUpDepth: depth,
    });
  }

  const enqueued = await enqueueTasks(env, tasks);

  await auditLog(env, {
    action: 'plan.attack',
    detail: `hybrid dispatch ${enqueued} tasks (${finalPlan.source})`,
    program: input.scope.program,
    meta: { scanId: input.scanId, source: finalPlan.source, count: enqueued },
  });

  return {
    enqueued,
    refused: refused.length,
    dedupKeys,
    source: finalPlan.source,
    rationale: finalPlan.rationale,
  };
}

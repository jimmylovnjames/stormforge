// StormForge Worker entry point.
//
// Routes:
//   GET  /                       -> dashboard (served from DASHBOARD_HTML)
//   POST /api/scan               -> start a scan (validates scope) -> {scanId}
//   GET  /api/scan/:id/status    -> live progress from the orchestrator DO
//   GET  /api/findings/:program  -> stored findings for a program
//   GET  /api/report/:program    -> Markdown disclosure draft
//   GET  /api/checks             -> list registered detection checks
//
// Every scan is refused unless its scope is explicitly authorized and every
// target is in-scope. There is no code path that performs active exploitation.

import type { Env, ScanRequest, Scope } from './types.js';
import { ScanOrchestrator } from './do/scan-orchestrator.js';
import { partitionByScope } from './scope/scope-guard.js';
import { FindingsStore } from './findings/store.js';
import { draftDisclosure } from './report/drafter.js';
import { listChecks } from './detect/registry.js';
import { DASHBOARD_HTML } from './dashboard-html.js';

export { ScanOrchestrator };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    try {
      if (request.method === 'GET' && pathname === '/') {
        return new Response(DASHBOARD_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
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
        return await handleReport(decodeURIComponent(reportMatch[1]), env);
      }

      if (request.method === 'GET' && pathname === '/api/checks') {
        return json({ checks: listChecks().map((c) => ({ id: c.id, title: c.title, cwe: c.cwe })) });
      }

      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: (e as Error).message }, 500);
    }
  },
};

async function handleStartScan(request: Request, env: Env): Promise<Response> {
  let req: ScanRequest;
  try {
    req = (await request.json()) as ScanRequest;
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const validationError = validateScanRequest(req);
  if (validationError) return json({ error: validationError }, 400);

  // Hard gate: refuse if any target is out of scope. We do not silently drop —
  // the operator must submit a clean, fully in-scope request.
  const { refused } = partitionByScope(req.targets, req.scope);
  if (refused.length > 0) {
    return json(
      { error: 'One or more targets are out of scope', refused },
      403,
    );
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
  // Reconstruct a minimal scope for formatting from the first finding's program.
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

function validateScanRequest(req: ScanRequest): string | null {
  if (!req || typeof req !== 'object') return 'Missing request body';
  if (!req.scope) return 'Missing scope';
  if (!req.scope.authorized) return 'Scope is not marked authorized. Confirm you have permission to test these assets.';
  if (!Array.isArray(req.scope.inScope) || req.scope.inScope.length === 0) return 'scope.inScope must list at least one authorized host';
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

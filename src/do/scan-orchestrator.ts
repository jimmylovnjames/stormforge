// Durable Object: coordinates a single scan's lifecycle and stores live state
// so the dashboard can poll progress. One DO instance per scan id gives us
// isolation and a natural place to persist incremental results.

import type { Env, ScanReport, ScanRequest } from '../types.js';
import { runScan } from '../engine/scanner.js';
import { FindingsStore } from '../findings/store.js';

interface ScanState {
  status: 'idle' | 'running' | 'done' | 'error';
  phase: string;
  probed: number;
  total: number;
  findings: number;
  report?: ScanReport;
  error?: string;
  startedAt?: string;
}

export class ScanOrchestrator {
  private state: ScanState = { status: 'idle', phase: '', probed: 0, total: 0, findings: 0 };

  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
  ) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.endsWith('/start') && request.method === 'POST') {
      if (this.state.status === 'running') {
        return json({ error: 'A scan is already running in this orchestrator' }, 409);
      }
      const req = (await request.json()) as ScanRequest;
      // Kick off asynchronously; return immediately so the client can poll.
      this.state = { status: 'running', phase: 'starting', probed: 0, total: 0, findings: 0, startedAt: new Date().toISOString() };
      this.ctx.waitUntil(this.execute(req));
      return json({ status: 'running' });
    }

    if (url.pathname.endsWith('/status')) {
      return json(this.state);
    }

    return json({ error: 'not found' }, 404);
  }

  private async execute(req: ScanRequest): Promise<void> {
    try {
      const report = await runScan(req, this.env, (ev) => {
        this.state = { ...this.state, phase: ev.phase, probed: ev.probed, total: ev.total, findings: ev.findings };
      });
      // Persist findings for cross-scan dedupe + reporting.
      const store = new FindingsStore(this.env.STORMFORGE_KV);
      await store.upsertMany(req.scope.program, report.findings);
      this.state = {
        status: 'done',
        phase: 'complete',
        probed: report.targetsProbed,
        total: report.targetsProbed,
        findings: report.findings.length,
        report,
        startedAt: this.state.startedAt,
      };
    } catch (e) {
      this.state = { ...this.state, status: 'error', error: (e as Error).message };
    }
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

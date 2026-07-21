// Durable Object: coordinates a single scan's lifecycle and stores live state
// so the dashboard can poll progress. One DO instance per scan id gives us
// isolation and a natural place to persist incremental results.

import type { Env, ScanReport, ScanRequest } from '../types.js';
import { runScan } from '../engine/scanner.js';
import { FindingsStore } from '../findings/store.js';
import { dispatchHybridFollowUp, shouldHybridDispatch } from '../tasks/hybrid.js';

interface ScanState {
  /** Stable id shared with hybrid executor tasks (DO name when using idFromName). */
  scanId?: string;
  status: 'idle' | 'running' | 'done' | 'error';
  phase: string;
  probed: number;
  total: number;
  findings: number;
  report?: ScanReport;
  error?: string;
  startedAt?: string;
  executorTasksEnqueued?: number;
}

export class ScanOrchestrator {
  private state: ScanState = { status: 'idle', phase: '', probed: 0, total: 0, findings: 0 };

  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
  ) {}

  private resolveScanId(req: ScanRequest): string {
    return this.ctx.id.name || req.scanId || crypto.randomUUID();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.endsWith('/start') && request.method === 'POST') {
      if (this.state.status === 'running') {
        return json({ error: 'A scan is already running in this orchestrator' }, 409);
      }
      const req = (await request.json()) as ScanRequest;
      const scanId = this.resolveScanId(req);
      this.state = {
        scanId,
        status: 'running',
        phase: 'starting',
        probed: 0,
        total: 0,
        findings: 0,
        startedAt: new Date().toISOString(),
      };
      this.ctx.waitUntil(this.execute({ ...req, scanId }));
      return json({ status: 'running', scanId });
    }

    if (url.pathname.endsWith('/status')) {
      return json({
        ...this.state,
        scanId: this.state.scanId || this.ctx.id.name,
      });
    }

    return json({ error: 'not found' }, 404);
  }

  private async execute(req: ScanRequest): Promise<void> {
    const scanId = req.scanId || this.resolveScanId(req);
    try {
      const report = await runScan({ ...req, scanId }, this.env, (ev) => {
        this.state = {
          ...this.state,
          scanId,
          phase: ev.phase,
          probed: ev.probed,
          total: ev.total,
          findings: ev.findings,
        };
      });
      const store = new FindingsStore(this.env.STORMFORGE_KV);
      await store.upsertMany(req.scope.program, report.findings, { keepRecon: true });

      let executorTasksEnqueued = 0;
      if (shouldHybridDispatch(this.env, req.scope)) {
        this.state = { ...this.state, phase: 'hybrid-dispatch' };
        const hybrid = await dispatchHybridFollowUp(this.env, {
          scanId: report.scanId,
          scope: req.scope,
          targets: req.targets,
          findings: report.findings,
          followUpDepth: 0,
        });
        executorTasksEnqueued = hybrid.enqueued;
      }

      this.state = {
        scanId: report.scanId,
        status: 'done',
        phase: 'complete',
        probed: report.targetsProbed,
        total: report.targetsProbed,
        findings: report.findings.length,
        report,
        startedAt: this.state.startedAt,
        executorTasksEnqueued,
      };
    } catch (e) {
      this.state = { ...this.state, scanId, status: 'error', error: (e as Error).message };
    }
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
